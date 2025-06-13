import socket
import struct
import threading
import time
from threading import Thread
from dns_cache import DNSCache  # Предполагается, что этот модуль существует


class DNSServer:
    def __init__(self, cache_file='dns_cache.json'):
        self.cache = DNSCache()
        self.cache_file = cache_file
        self.running = False
        self.cleanup_thread = None
        self.console_thread = None
        self.lock = threading.Lock()
        self.cleanup_interval = 30
        self.socket_timeout = 1.0
        self.forwarder = ('8.8.8.8', 53)  # Google DNS

    def start(self, host='0.0.0.0', port=53):
        """Запуск DNS сервера с обработкой основных исключений"""
        try:
            self.running = True
            self._load_cache()

            # Запуск фоновых потоков
            self.cleanup_thread = Thread(target=self._cleanup_worker, daemon=True)
            self.console_thread = Thread(target=self._console_worker, daemon=True)
            self.cleanup_thread.start()
            self.console_thread.start()

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind((host, port))
                sock.settimeout(self.socket_timeout)
                print(f"[INFO] DNS сервер запущен на {host}:{port}")
                print("[INFO] Доступные команды: !help, !stop, !save")

                self._server_loop(sock)

        except PermissionError:
            print(f"[ERROR] Требуются права администратора для порта {port}")
        except Exception as e:
            print(f"[CRITICAL] Фатальная ошибка: {str(e)}")
        finally:
            self.stop()

    def stop(self):
        """Безопасная остановка сервера"""
        with self.lock:
            self.running = False

        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=2.0)

        self._save_cache()
        print("[INFO] Сервер остановлен")

    def _load_cache(self):
        """Загрузка кеша с обработкой ошибок"""
        try:
            self.cache.load_from_file(self.cache_file)
        except Exception as e:
            print(f"[WARNING] Ошибка загрузки кеша: {str(e)}")

    def _save_cache(self):
        """Сохранение кеша с обработкой ошибок"""
        try:
            self.cache.cleanup()
            self.cache.save_to_file(self.cache_file)
        except Exception as e:
            print(f"[WARNING] Ошибка сохранения кеша: {str(e)}")

    def _server_loop(self, sock):
        """Основной цикл сервера"""
        while self.running:
            try:
                data, addr = sock.recvfrom(512)
                Thread(target=self._handle_request, args=(sock, data, addr)).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:  # Игнорируем ошибки после остановки
                    print(f"[ERROR] Ошибка в основном цикле: {str(e)}")

    def _cleanup_worker(self):
        """Периодическая очистка кеша"""
        while self.running:
            try:
                self.cache.cleanup()
                for _ in range(self.cleanup_interval):
                    if not self.running:
                        break
                    time.sleep(1)
            except Exception as e:
                print(f"[ERROR] Ошибка в cleanup worker: {str(e)}")

    def _console_worker(self):
        """Обработчик консольных команд"""
        commands = {
            '!help': self._show_help,
            '!stop': self._stop_command,
            '!save': self._save_command
        }

        while self.running:
            try:
                cmd = input().strip().lower()
                if cmd in commands:
                    commands[cmd]()
                else:
                    print(f"Неизвестная команда: {cmd}")
            except Exception as e:
                print(f"[ERROR] Ошибка обработки команды: {str(e)}")

    def _show_help(self):
        print("Доступные команды:")
        print("!help - показать справку")
        print("!stop - остановить сервер")
        print("!save - сохранить кеш в файл")

    def _stop_command(self):
        print("[INFO] Получена команда на остановку...")
        with self.lock:
            self.running = False

    def _save_command(self):
        print("[INFO] Сохранение кеша...")
        self._save_cache()

    def _handle_request(self, sock, data, addr):
        """Обработка DNS запроса"""
        try:
            if len(data) < 12:
                print(f"[WARNING] Получен слишком короткий пакет от {addr}")
                return

            # Разбор заголовка DNS
            transaction_id = data[:2]
            flags = data[2:4]

            # Пропускаем ответы (не запросы)
            if flags[0] & 0x80:
                return

            # Разбор вопроса
            try:
                query, offset = self._parse_name(data, 12)
                qtype = data[offset:offset + 2]
            except Exception as e:
                print(f"[WARNING] Ошибка разбора DNS запроса: {str(e)}")
                return

            # Проверка кеша
            cached = self._get_cached_response(transaction_id, query, qtype)
            if cached:
                sock.sendto(cached, addr)
                return

            # Пересылка запроса
            response = self._forward_query(data)
            if response:
                try:
                    self._cache_response(response)
                    sock.sendto(response, addr)
                except Exception as e:
                    print(f"[ERROR] Ошибка обработки ответа: {str(e)}")

        except Exception as e:
            print(f"[ERROR] Ошибка обработки запроса: {str(e)}")

    def _get_cached_response(self, tid, query, qtype):
        """Поиск ответа в кеше"""
        try:
            if qtype == b'\x00\x01':  # A record
                ips = self.cache.get_ip(query)
                if ips:
                    return self._build_response(tid, query, qtype, ips)
            elif qtype == b'\x00\x0c':  # PTR record
                domains = self.cache.get_domain(query)
                if domains:
                    return self._build_response(tid, query, qtype, domains)
        except Exception as e:
            print(f"[WARNING] Ошибка проверки кеша: {str(e)}")
        return None

    def _forward_query(self, query_data):
        """Пересылка запроса на внешний DNS"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(5.0)
                s.sendto(query_data, self.forwarder)
                return s.recvfrom(512)[0]
        except socket.timeout:
            print("[WARNING] Таймаут DNS запроса")
        except Exception as e:
            print(f"[ERROR] Ошибка пересылки запроса: {str(e)}")
        return None

    def _cache_response(self, response):
        """Кеширование ответа"""
        try:
            offset = 12
            # Пропускаем вопрос
            _, offset = self._parse_name(response, offset)
            offset += 4  # QTYPE + QCLASS

            # Обработка ответов
            ancount = struct.unpack('!H', response[6:8])[0]
            for _ in range(ancount):
                name, offset = self._parse_name(response, offset)
                rtype, _, ttl, rdlength = struct.unpack('!HHIH', response[offset:offset + 10])
                offset += 10
                rdata = response[offset:offset + rdlength]
                offset += rdlength

                if rtype == 1:  # A record
                    self.cache.add_record(name, socket.inet_ntoa(rdata), ttl)
                elif rtype == 12:  # PTR record
                    domain, _ = self._parse_name(response, offset - rdlength)
                    self.cache.add_record(name, domain, ttl)
        except Exception as e:
            print(f"[WARNING] Ошибка кеширования ответа: {str(e)}")

    def _build_response(self, tid, query, qtype, answers):
        """Построение DNS ответа"""
        try:
            header = tid + b'\x81\x80\x00\x01' + struct.pack('!H', len(answers)) + b'\x00\x00\x00\x00'
            question = self._encode_name(query) + qtype + b'\x00\x01'
            answers_section = self._build_answers_section(qtype, answers)
            return header + question + answers_section
        except Exception as e:
            print(f"[ERROR] Ошибка построения ответа: {str(e)}")
            raise

    def _build_answers_section(self, qtype, answers):
        """Формирование секции ответов"""
        section = b''
        try:
            for answer in answers:
                if qtype == b'\x00\x01':  # A record
                    section += b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + socket.inet_aton(answer)
                elif qtype == b'\x00\x0c':  # PTR record
                    encoded = self._encode_name(answer)
                    section += b'\xc0\x0c\x00\x0c\x00\x01\x00\x00\x00\x3c' + struct.pack('!H', len(encoded)) + encoded
        except Exception as e:
            print(f"[ERROR] Ошибка формирования ответов: {str(e)}")
            raise
        return section

    def _parse_name(self, data, offset):
        """Разбор DNS имени"""
        try:
            name = []
            while True:
                length = data[offset]
                if length == 0:
                    offset += 1
                    break
                if (length & 0xc0) == 0xc0:  # Указатель
                    pointer = struct.unpack('!H', data[offset:offset + 2])[0] & 0x3fff
                    part, _ = self._parse_name(data, pointer)
                    name.append(part)
                    offset += 2
                    break
                offset += 1
                name.append(data[offset:offset + length].decode('ascii'))
                offset += length
            return '.'.join(name), offset
        except Exception as e:
            print(f"[ERROR] Ошибка разбора имени: {str(e)}")
            raise

    def _encode_name(self, name):
        """Кодирование DNS имени"""
        try:
            return b''.join(
                struct.pack('!B', len(part)) + part.encode('ascii')
                for part in name.split('.')
            ) + b'\x00'
        except Exception as e:
            print(f"[ERROR] Ошибка кодирования имени: {str(e)}")
            raise