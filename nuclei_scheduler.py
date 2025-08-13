#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Nuclei Zamanlayıcı (Kill & Resume Destekli) - Final Versiyon

Özellikler:
- Belirtilen saatlerde nuclei başlatır ve durdurur
- Kill sonrası resume dosyasını kaydeder
- Sonraki çalışmada resume ile devam eder
- Resume'da output dosyasına saat-gün-ay ekler
- Logları append modunda tutar
- Tarama bitince yeni tarama başlatmaz

Kullanım:
    python3 nuclei_scheduler.py "nuclei -duc -ni -l httpx.txt -c 200 -es info,low -o nuclei-result.txt"
    python3 nuclei_scheduler.py "nuclei -l targets.txt -t templates/ -o output.txt"
    python3 nuclei_scheduler.py "nuclei -duc -ni -l httpx.txt -c 100 -es info,low -etags wordpress,wp-plugin -o nuclei-result.txt"
"""

import sys
import os
import subprocess
import time
import datetime
import signal
import atexit
import json
import hashlib
import re
import logging
import shlex
import threading
import shutil
from pathlib import Path


# --- Global Değişkenler ---
nuclei_process = None
command_id = None
last_resume_file = None
output_thread = None
scan_completed = False
process_killed_by_scheduler = False
original_pid = None  # Başlatılan process'in PID'si


# --- Loglama Ayarları ---
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

for handler in logger.handlers[:]:
    logger.removeHandler(handler)

try:
    LOG_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'nuclei_scheduler.log')
except NameError:
    LOG_FILE_PATH = os.path.join(os.getcwd(), 'nuclei_scheduler.log')

# APPEND modunda aç - eski logları SİLME
file_handler = logging.FileHandler(LOG_FILE_PATH, mode='a', encoding='utf-8')
file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(asctime)s - %(message)s')
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)


# --- ZAMANLAMA AYARLARI ---
WEEKDAY_SCAN_ENABLED = True
WEEKEND_SCAN_ENABLED = False

WEEKDAY_SCAN_WINDOW = {
    'start': datetime.time(1, 0),   # 01:00
    'end': datetime.time(7, 0)      # 07:00
}

SATURDAY_SCAN_WINDOW = {
    'start': datetime.time(0, 10)   # 00:10
}
SUNDAY_SCAN_WINDOW = {
    'end': datetime.time(23, 50)    # 23:50
}

STATE_FILE_PATH = os.path.join(os.path.expanduser("~"), ".nuclei_scheduler_state.json")

# Resume dosyası regex'leri
RESUME_FILE_REGEXES = [
    r"Creating resume file:\s*(.*?\.cfg)",
    r"Resume file:\s*(.*?\.cfg)",
    r"Saving resume config to:\s*(.*?\.cfg)",
    r"Writing resume file:\s*(.*?\.cfg)"
]

# Tarama tamamlanma mesajları
SCAN_COMPLETED_PATTERNS = [
    r"All templates executed",
    r"Scan completed",
    r"No more templates to run",
    r"Templates executed successfully",
    r"Finished executing templates",
    r"No results found",
    r"Nuclei execution completed"
]

RESUME_FILES_RETENTION_DAYS = 7


def get_command_id(command_list):
    """Komut için benzersiz ID oluştur"""
    command_str = " ".join(command_list)
    return hashlib.sha1(command_str.encode()).hexdigest()


def is_process_running(pid):
    """PID'ye sahip process çalışıyor mu kontrol et"""
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def cleanup_old_resume_files(directory, days_to_keep=RESUME_FILES_RETENTION_DAYS):
    """Eski resume dosyalarını temizle"""
    try:
        if not os.path.exists(directory):
            return
        
        cutoff_time = time.time() - (days_to_keep * 24 * 60 * 60)
        pattern = re.compile(r'\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}_[a-f0-9]{8}_.*\.cfg$')
        
        deleted_count = 0
        for file_path in Path(directory).glob('*.cfg'):
            if pattern.match(file_path.name):
                if file_path.stat().st_mtime < cutoff_time:
                    file_path.unlink()
                    logger.debug(f"Eski resume dosyası silindi: {file_path}")
                    deleted_count += 1
        
        if deleted_count > 0:
            logger.info(f"🗑️ {deleted_count} adet eski resume dosyası temizlendi")
            
    except Exception as e:
        logger.warning(f"Eski resume dosyaları temizlenemedi: {e}")


def archive_resume_file(original_path, cmd_id):
    """Resume dosyasını arşivle"""
    if not original_path or not os.path.exists(original_path):
        logger.warning(f"Arşivlenecek resume dosyası bulunamadı: {original_path}")
        return None
    
    try:
        now_str = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        dir_name = os.path.dirname(original_path) or '.'
        base_name = os.path.basename(original_path)
        name_parts = os.path.splitext(base_name)
        
        new_name = f"{now_str}_{cmd_id[:8]}_{name_parts[0]}{name_parts[1]}"
        new_path = os.path.join(dir_name, new_name)
        
        shutil.copy2(original_path, new_path)
        logger.info(f"✅ Resume dosyası arşivlendi: {new_path}")
        
        cleanup_old_resume_files(dir_name)
        return new_path
        
    except Exception as e:
        logger.error(f"Resume dosyası arşivlenemedi: {e}")
        return original_path


def _atomic_write_json(path, data):
    """JSON dosyasını atomik olarak yaz"""
    temp_path = path + '.tmp'
    try:
        with open(temp_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(temp_path, path)
    except Exception as e:
        logger.error(f"Atomik yazma hatası: {e}")
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except:
                pass
        raise


def save_resume_state(cmd_id, resume_file_path, is_completed=False):
    """Resume durumunu kaydet"""
    try:
        states = {}
        if os.path.exists(STATE_FILE_PATH):
            try:
                with open(STATE_FILE_PATH, 'r', encoding='utf-8') as f:
                    states = json.load(f)
            except json.JSONDecodeError:
                logger.warning("Durum dosyası bozuk, yeniden oluşturuluyor")
                states = {}
        
        states[cmd_id] = {
            'resume_file': resume_file_path if not is_completed else None,
            'timestamp': datetime.datetime.now().isoformat(),
            'command': sys.argv[1:],
            'completed': is_completed,
            'killed_by_scheduler': process_killed_by_scheduler
        }
        
        _atomic_write_json(STATE_FILE_PATH, states)
        
        if is_completed:
            logger.info(f"✅ Tarama TAMAMLANDI olarak işaretlendi - Komut ID: {cmd_id[:8]}")
        else:
            logger.info(f"💾 Resume durumu kaydedildi - Komut ID: {cmd_id[:8]}")
        
    except Exception as e:
        logger.error(f"Resume durumu kaydedilemedi: {e}")


def load_resume_state(cmd_id):
    """Resume durumunu yükle"""
    try:
        if not os.path.exists(STATE_FILE_PATH):
            return None, False
        
        with open(STATE_FILE_PATH, 'r', encoding='utf-8') as f:
            states = json.load(f)
        
        state_info = states.get(cmd_id)
        if not state_info:
            return None, False
        
        if isinstance(state_info, str):
            resume_file = state_info
            is_completed = False
        else:
            resume_file = state_info.get('resume_file')
            is_completed = state_info.get('completed', False)
            
            if is_completed:
                logger.info(f"ℹ️ Bu komut için tarama TAMAMLANMIŞ - Komut ID: {cmd_id[:8]}")
                return None, True
        
        if resume_file and os.path.exists(resume_file):
            logger.info(f"📂 Resume dosyası bulundu - Komut ID: {cmd_id[:8]}")
            return resume_file, False
        elif resume_file:
            logger.warning(f"Resume dosyası kayıtlı ama bulunamadı: {resume_file}")
            
    except Exception as e:
        logger.error(f"Resume durumu yüklenemedi: {e}")
    
    return None, False


def parse_resume_file_from_output(output_line):
    """Nuclei çıktısından resume dosyasını parse et"""
    for pattern in RESUME_FILE_REGEXES:
        match = re.search(pattern, output_line, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return None


def check_scan_completed(output_line):
    """Tarama tamamlandı mı kontrol et"""
    for pattern in SCAN_COMPLETED_PATTERNS:
        if re.search(pattern, output_line, re.IGNORECASE):
            return True
    return False


def stream_reader(stream):
    """Nuclei çıktısını oku"""
    global last_resume_file, scan_completed
    
    try:
        for line in iter(stream.readline, ''):
            if not line:
                break
            
            clean_line = line.strip()
            if clean_line:
                # Her satırı logla
                logger.info(f"[Nuclei] {clean_line}")
                
                # Resume dosyasını yakala
                resume_file = parse_resume_file_from_output(clean_line)
                if resume_file:
                    logger.info(f"🔍 Resume dosyası tespit edildi: {resume_file}")
                    last_resume_file = resume_file
                
                # Tarama tamamlandı mı?
                if check_scan_completed(clean_line):
                    logger.info(f"🎉 Tarama TAMAMLANDI sinyali alındı")
                    scan_completed = True
                    
    except Exception as e:
        logger.error(f"Stream okuma hatası: {e}")
    finally:
        try:
            stream.close()
        except:
            pass


def is_running_window_at_time(t):
    """Belirtilen zaman tarama penceresi içinde mi?"""
    weekday = t.weekday()
    current_time = t.time()
    
    if 0 <= weekday <= 4:  # Hafta içi
        if not WEEKDAY_SCAN_ENABLED:
            return False
        
        if WEEKDAY_SCAN_WINDOW['start'] > WEEKDAY_SCAN_WINDOW['end']:
            # Gece yarısını geçiyor
            return (current_time >= WEEKDAY_SCAN_WINDOW['start'] or
                    current_time <= WEEKDAY_SCAN_WINDOW['end'])
        else:
            return WEEKDAY_SCAN_WINDOW['start'] <= current_time <= WEEKDAY_SCAN_WINDOW['end']
    
    elif weekday >= 5:  # Hafta sonu
        if not WEEKEND_SCAN_ENABLED:
            return False
        
        if weekday == 5:  # Cumartesi
            return current_time >= SATURDAY_SCAN_WINDOW['start']
        if weekday == 6:  # Pazar
            return current_time <= SUNDAY_SCAN_WINDOW['end']
    
    return False


def is_running_window():
    """Şu an tarama penceresi içinde mi?"""
    return is_running_window_at_time(datetime.datetime.now())


def format_timedelta(td):
    """Zaman farkını formatla"""
    if not isinstance(td, datetime.timedelta) or td.total_seconds() < 0:
        return "Hesaplanamadı"
    
    total_seconds = int(td.total_seconds())
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    parts = []
    if days > 0:
        parts.append(f"{days} gün")
    if hours > 0:
        parts.append(f"{hours} saat")
    if minutes > 0:
        parts.append(f"{minutes} dakika")
    
    return ", ".join(parts) if parts else "Birkaç saniye"


def get_next_times():
    """Sonraki başlama/durdurma zamanlarını hesapla"""
    now = datetime.datetime.now()
    today = now.date()
    
    schedule = []
    if WEEKDAY_SCAN_ENABLED:
        schedule.append({
            'days': range(0, 5),
            'start': WEEKDAY_SCAN_WINDOW['start'],
            'end': WEEKDAY_SCAN_WINDOW['end'],
            'type': 'weekday'
        })
    
    if WEEKEND_SCAN_ENABLED:
        schedule.append({
            'days': range(5, 7),
            'start': SATURDAY_SCAN_WINDOW['start'],
            'end': SUNDAY_SCAN_WINDOW['end'],
            'type': 'weekend'
        })
    
    if not schedule:
        return None, None
    
    potential_events = []
    
    for i in range(14):
        current_date = today + datetime.timedelta(days=i)
        weekday = current_date.weekday()
        
        for window in schedule:
            if weekday in window['days']:
                if window['type'] == 'weekend':
                    if weekday == 5:
                        start_dt = datetime.datetime.combine(current_date, window['start'])
                        end_dt = datetime.datetime.combine(
                            current_date + datetime.timedelta(days=1),
                            window['end']
                        )
                        potential_events.append({'type': 'start', 'time': start_dt})
                        potential_events.append({'type': 'stop', 'time': end_dt})
                else:
                    start_dt = datetime.datetime.combine(current_date, window['start'])
                    end_dt = datetime.datetime.combine(current_date, window['end'])
                    
                    if start_dt > end_dt:
                        end_dt += datetime.timedelta(days=1)
                    
                    potential_events.append({'type': 'start', 'time': start_dt})
                    potential_events.append({'type': 'stop', 'time': end_dt})
                break
    
    future_events = sorted(
        [e for e in potential_events if e['time'] > now],
        key=lambda x: x['time']
    )
    
    if not future_events:
        return None, None
    
    next_start = None
    next_stop = None
    currently_running = is_running_window()
    
    if currently_running:
        for event in future_events:
            if event['type'] == 'stop':
                next_stop = event['time']
                break
        
        if next_stop:
            for event in future_events:
                if event['type'] == 'start' and event['time'] > next_stop:
                    next_start = event['time']
                    break
    else:
        for event in future_events:
            if event['type'] == 'start':
                next_start = event['time']
                break
        
        if next_start:
            for event in future_events:
                if event['type'] == 'stop' and event['time'] > next_start:
                    next_stop = event['time']
                    break
    
    return next_start, next_stop


def _find_output_flag_index(args):
    """Output flag indeksini bul"""
    candidate_flags = {'-o', '-output', '--output', '--output-file'}
    for idx, token in enumerate(args):
        if token in candidate_flags:
            return idx
    return -1


def _append_datetime_suffix_to_output(path):
    """Output dosyasına saat-gün-ay ekle"""
    base_dir = os.path.dirname(path) or '.'
    base_name = os.path.basename(path)
    name, ext = os.path.splitext(base_name)
    
    # SAAT-GÜN-AY formatı
    now = datetime.datetime.now()
    suffix = now.strftime("-%H-%d-%m")
    
    new_name = f"{name}{suffix}{ext}"
    new_path = os.path.join(base_dir, new_name)
    
    return new_path


def _maybe_update_output_for_resume(command_to_run):
    """Resume için output dosyasını güncelle"""
    output_idx = _find_output_flag_index(command_to_run)
    
    if output_idx == -1:
        logger.warning("⚠️ Output flag bulunamadı")
        return None
    
    value_idx = output_idx + 1
    if value_idx >= len(command_to_run):
        logger.warning("⚠️ Output değeri eksik")
        return None
    
    original_output = command_to_run[value_idx]
    new_output = _append_datetime_suffix_to_output(original_output)
    command_to_run[value_idx] = new_output
    
    logger.info(f"📝 Resume output: {original_output} → {new_output}")
    return new_output


def check_process_status():
    """Process durumunu kontrol et"""
    global nuclei_process, scan_completed, original_pid
    
    if not nuclei_process:
        return False
    
    poll_result = nuclei_process.poll()
    
    if poll_result is None:
        # Process çalışıyor
        if original_pid and is_process_running(original_pid):
            return True
        else:
            logger.warning(f"⚠️ Process (PID: {original_pid}) kayboldu!")
            nuclei_process = None
            return False
    else:
        # Process sonlandı
        if poll_result == 0:
            logger.info(f"✅ Nuclei normal tamamlandı (exit: 0)")
            scan_completed = True
        elif poll_result == -2 or poll_result == 130:
            if process_killed_by_scheduler:
                logger.info(f"✅ Nuclei scheduler tarafından durduruldu")
            else:
                logger.warning(f"⚠️ Nuclei dışarıdan durduruldu")
        else:
            logger.warning(f"⚠️ Nuclei hata ile sonlandı: {poll_result}")
        
        nuclei_process = None
        return False


def stop_nuclei_gracefully():
    """Nuclei'yi düzgün durdur"""
    global nuclei_process, command_id, last_resume_file, process_killed_by_scheduler, scan_completed, original_pid
    
    if not nuclei_process:
        return True
    
    poll_result = nuclei_process.poll()
    if poll_result is not None:
        logger.info(f"ℹ️ Process zaten sonlanmış")
        nuclei_process = None
        return True
    
    pid = original_pid or nuclei_process.pid
    
    if not is_process_running(pid):
        logger.warning(f"⚠️ Process (PID: {pid}) bulunamadı")
        nuclei_process = None
        return True
    
    logger.info(f"🛑 Nuclei (PID: {pid}) durduruluyor...")
    process_killed_by_scheduler = True
    
    try:
        nuclei_process.send_signal(signal.SIGINT)
        logger.info(f"📤 SIGINT gönderildi")
        
        nuclei_process.wait(timeout=30)
        exit_code = nuclei_process.returncode
        
        logger.info(f"✅ Nuclei durduruldu (exit: {exit_code})")
        
        # Resume dosyasını kaydet
        if not scan_completed and last_resume_file and command_id:
            archived_path = archive_resume_file(last_resume_file, command_id)
            if archived_path:
                save_resume_state(command_id, archived_path, is_completed=False)
                logger.info(f"💾 Resume kaydedildi: {archived_path}")
        elif scan_completed:
            save_resume_state(command_id, None, is_completed=True)
            logger.info("ℹ️ Tarama tamamlandı, resume gerekmez")
        else:
            logger.warning("⚠️ Resume dosyası bulunamadı")
        
        return True
        
    except subprocess.TimeoutExpired:
        logger.warning(f"⚠️ Timeout, zorla sonlandırılıyor")
        try:
            nuclei_process.kill()
            nuclei_process.wait(timeout=5)
        except:
            pass
        return False
    except Exception as e:
        logger.error(f"Durdurma hatası: {e}")
        return False
    finally:
        nuclei_process = None
        original_pid = None
        process_killed_by_scheduler = False


def cleanup_on_exit():
    """Çıkışta temizlik"""
    if nuclei_process and nuclei_process.poll() is None:
        logger.info(f"⛔ Script kapanıyor...")
        stop_nuclei_gracefully()


def print_startup_banner():
    """Başlangıç bilgileri"""
    logger.info("="*70)
    logger.info("🚀 NUCLEI SCHEDULER BAŞLATILDI")
    logger.info("="*70)
    logger.info(f"📅 Tarih: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"📁 Log: {LOG_FILE_PATH}")
    logger.info(f"💾 Durum: {STATE_FILE_PATH}")
    logger.info(f"🔧 PID: {os.getpid()}")
    logger.info("-"*70)
    logger.info("⏰ ZAMANLAMA:")
    
    if WEEKDAY_SCAN_ENABLED:
        logger.info(f"  ✅ Hafta İçi: {WEEKDAY_SCAN_WINDOW['start']} - {WEEKDAY_SCAN_WINDOW['end']}")
    else:
        logger.info("  ❌ Hafta İçi: Kapalı")
    
    if WEEKEND_SCAN_ENABLED:
        logger.info(f"  ✅ Hafta Sonu: {SATURDAY_SCAN_WINDOW['start']} - {SUNDAY_SCAN_WINDOW['end']}")
    else:
        logger.info("  ❌ Hafta Sonu: Kapalı")
    
    logger.info("="*70)


def main():
    """Ana döngü"""
    global nuclei_process, command_id, last_resume_file, output_thread, scan_completed, process_killed_by_scheduler, original_pid
    
    # Parametre kontrolü
    if len(sys.argv) < 2:
        print("❌ Hata: Nuclei komutu eksik!")
        print(f"Kullanım: {sys.argv[0]} \"nuclei -l targets.txt -o output.txt\"")
        sys.exit(1)
    
    # Komutu parse et
    raw_args = sys.argv[1:]
    base_command = shlex.split(raw_args[0]) if len(raw_args) == 1 and ' ' in raw_args[0] else raw_args
    
    if not base_command or 'nuclei' not in base_command[0]:
        print("❌ Hata: 'nuclei' ile başlamalı")
        sys.exit(1)
    
    # Komut ID
    command_id = get_command_id(base_command)
    
    # Banner
    print_startup_banner()
    logger.info(f"🔑 ID: {command_id[:8]}")
    logger.info(f"📌 Komut: {' '.join(base_command)}")
    logger.info("="*70)
    
    # Cleanup
    atexit.register(cleanup_on_exit)
    
    scan_started_in_window = False
    last_status_log = 0
    scan_already_completed = False
    
    # Önceki durum kontrolü
    resume_file, is_completed = load_resume_state(command_id)
    if is_completed:
        logger.info("⚠️ TARAMA DAHA ÖNCE TAMAMLANMIŞ!")
        logger.info("💡 Yeni tarama için --reset kullanın")
        scan_already_completed = True
    
    try:
        while True:
            try:
                # Tamamlanmış tarama kontrolü
                if scan_already_completed:
                    if time.time() - last_status_log > 300:
                        logger.info("⏸️ Tarama tamamlandı, bekleme modunda...")
                        last_status_log = time.time()
                    time.sleep(30)
                    continue
                
                # Durum kontrolü
                should_run = is_running_window()
                is_running = check_process_status()
                now = datetime.datetime.now()
                next_start, next_stop = get_next_times()
                
                # Pencere dışında flag sıfırla
                if not should_run:
                    scan_started_in_window = False
                
                # Process sonlandıysa ve tarama tamamlandıysa
                if not is_running and scan_completed:
                    save_resume_state(command_id, None, is_completed=True)
                    scan_already_completed = True
                    logger.info("🎉 TARAMA TAMAMLANDI - YENİ TARAMA BAŞLATILMAYACAK!")
                    continue
                
                # Durum logu (5 dakikada bir)
                if time.time() - last_status_log > 300:
                    if is_running:
                        pid = original_pid or (nuclei_process.pid if nuclei_process else "?")
                        if next_stop:
                            time_left = next_stop - now
                            logger.info(f"🟢 Çalışıyor (PID: {pid}) | Durdurulmasına: {format_timedelta(time_left)}")
                        else:
                            logger.info(f"🟢 Çalışıyor (PID: {pid})")
                    else:
                        if next_start:
                            time_left = next_start - now
                            logger.info(f"🔴 Beklemede | Başlamasına: {format_timedelta(time_left)}")
                        else:
                            logger.info(f"🔴 Beklemede")
                    
                    last_status_log = time.time()
                
                # TARAMA PENCERESİ İÇİNDE
                if should_run:
                    if not is_running and not scan_started_in_window and not scan_completed:
                        command_to_run = list(base_command)
                        resume_file, _ = load_resume_state(command_id)
                        
                        if resume_file:
                            logger.info("="*70)
                            logger.info("🔄 RESUME MODU")
                            
                            if not os.path.exists(resume_file):
                                logger.error(f"❌ Resume dosyası yok: {resume_file}")
                                resume_file = None
                            else:
                                # OUTPUT DOSYASINI GÜNCELLE (SAAT-GÜN-AY)
                                _maybe_update_output_for_resume(command_to_run)
                                command_to_run.extend(['-resume', resume_file])
                                logger.info(f"📂 Resume: {resume_file}")
                        
                        if not resume_file:
                            logger.info("="*70)
                            logger.info("🆕 YENİ TARAMA")
                        
                        logger.info(f"▶️ {' '.join(command_to_run)}")
                        logger.info("="*70)
                        
                        # Process başlat
                        last_resume_file = None
                        scan_completed = False
                        process_killed_by_scheduler = False
                        
                        try:
                            nuclei_process = subprocess.Popen(
                                command_to_run,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                text=True,
                                encoding='utf-8',
                                errors='replace',
                                bufsize=1
                            )
                            
                            original_pid = nuclei_process.pid
                            scan_started_in_window = True
                            
                            # Output thread
                            output_thread = threading.Thread(
                                target=stream_reader,
                                args=(nuclei_process.stdout,),
                                daemon=True
                            )
                            output_thread.start()
                            
                            logger.info(f"✅ Nuclei başlatıldı (PID: {original_pid})")
                            logger.info("="*70)
                            
                        except Exception as e:
                            logger.error(f"❌ Başlatma hatası: {e}")
                            nuclei_process = None
                            original_pid = None
                
                # TARAMA PENCERESİ DIŞINDA
                else:
                    if is_running:
                        logger.info("="*70)
                        logger.info("⏸️ TARAMA PENCERESİ DIŞINDA - DURDURULUYOR")
                        
                        if stop_nuclei_gracefully():
                            logger.info("✅ Nuclei durduruldu, resume kaydedildi")
                        else:
                            logger.warning("⚠️ Nuclei zorla sonlandırıldı")
                        
                        logger.info("="*70)
                
                # 30 saniye bekle
                time.sleep(30)
                
            except Exception as e:
                logger.error(f"Döngü hatası: {e}", exc_info=True)
                time.sleep(60)
                
    except KeyboardInterrupt:
        logger.info("\n" + "="*70)
        logger.info("⛔ Ctrl+C ile durduruldu")
        logger.info("="*70)
    except Exception as e:
        logger.critical(f"Kritik hata: {e}", exc_info=True)
    finally:
        logger.info("="*70)
        logger.info("🔚 KAPATILIYOR...")
        
        if nuclei_process and nuclei_process.poll() is None:
            stop_nuclei_gracefully()
        
        if scan_completed:
            logger.info("📊 Durum: Tarama TAMAMLANDI ✅")
        elif last_resume_file:
            logger.info(f"📊 Durum: Resume kaydedildi 💾")
        else:
            logger.info("📊 Durum: Aktif tarama yok")
        
        logger.info("✅ Kapatıldı")
        logger.info("="*70)


if __name__ == "__main__":
    # --reset parametresi
    if len(sys.argv) > 1 and sys.argv[1] == '--reset':
        print("🔄 Durum sıfırlanıyor...")
        try:
            if os.path.exists(STATE_FILE_PATH):
                os.remove(STATE_FILE_PATH)
                print("✅ Durum dosyası silindi")
            else:
                print("ℹ️ Durum dosyası zaten yok")
        except Exception as e:
            print(f"❌ Hata: {e}")
        sys.exit(0)
    
    main()
