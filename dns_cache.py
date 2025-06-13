import time
import json
from threading import Lock
from typing import Dict, List, Optional, Tuple


class DNSCache:
    """
    Класс для кэширования DNS-записей с поддержкой:
    - Прямого (домен → IP) и обратного (IP → домен) отображения
    - Хранения NS-записей
    - Автоматической очистки устаревших записей
    - Сериализации/десериализации состояния
    """

    def __init__(self):
        """Инициализация структур данных для хранения кэша."""
        self.domain_to_ip: Dict[str, Dict[str, Tuple[float, int]]] = {}
        self.ip_to_domain: Dict[str, Dict[str, Tuple[float, int]]] = {}
        self.ns_records: Dict[str, Dict[str, Tuple[float, int]]] = {}
        self.lock = Lock()

    def add_record(self, domain: str, ip: str, ttl: int) -> None:
        """
        Добавляет A/AAAA запись в кэш.

        Args:
            domain: Доменное имя
            ip: IP-адрес
            ttl: Время жизни записи в секундах
        """
        expire_time = time.time() + ttl
        with self.lock:
            self._add_to_dict(self.domain_to_ip, domain, ip, expire_time, ttl)
            self._add_to_dict(self.ip_to_domain, ip, domain, expire_time, ttl)

    def add_ns_record(self, domain: str, nameserver: str, ttl: int) -> None:
        """
        Добавляет NS-запись в кэш.

        Args:
            domain: Доменное имя
            nameserver: NS-сервер
            ttl: Время жизни записи в секундах
        """
        expire_time = time.time() + ttl
        with self.lock:
            self._add_to_dict(self.ns_records, domain, nameserver, expire_time, ttl)

    def get_ip(self, domain: str) -> Optional[List[str]]:
        """
        Возвращает IP-адреса для домена.

        Args:
            domain: Доменное имя

        Returns:
            Список актуальных IP-адресов или None
        """
        return self._get_valid_entries(self.domain_to_ip, domain)

    def get_domain(self, ip: str) -> Optional[List[str]]:
        """
        Возвращает домены для IP-адреса.

        Args:
            ip: IP-адрес

        Returns:
            Список доменных имен или None
        """
        return self._get_valid_entries(self.ip_to_domain, ip)

    def get_nameservers(self, domain: str) -> Optional[List[str]]:
        """
        Возвращает NS-серверы для домена.

        Args:
            domain: Доменное имя

        Returns:
            Список NS-серверов или None
        """
        return self._get_valid_entries(self.ns_records, domain)

    def cleanup(self) -> None:
        """Очищает кэш от устаревших записей."""
        current_time = time.time()
        with self.lock:
            self._cleanup_dict(self.domain_to_ip, current_time)
            self._cleanup_dict(self.ip_to_domain, current_time)
            self._cleanup_dict(self.ns_records, current_time)

    def save_to_file(self, filename: str) -> None:
        """
        Сохраняет кэш в файл.

        Args:
            filename: Путь к файлу для сохранения
        """
        with self.lock:
            data = {
                'domain_to_ip': self._prepare_for_serialization(self.domain_to_ip),
                'ip_to_domain': self._prepare_for_serialization(self.ip_to_domain),
                'ns_records': self._prepare_for_serialization(self.ns_records),
                'timestamp': time.time()
            }

            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
            except IOError as e:
                print(f"[ERROR] Ошибка сохранения кэша: {e}")

    def load_from_file(self, filename: str) -> None:
        """
        Загружает кэш из файла.

        Args:
            filename: Путь к файлу с сохраненным кэшем
        """
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                data = json.load(f)

            load_time = time.time()
            time_passed = load_time - data.get('timestamp', load_time)

            with self.lock:
                self.domain_to_ip = self._restore_from_serialized(
                    data.get('domain_to_ip', {}), time_passed)
                self.ip_to_domain = self._restore_from_serialized(
                    data.get('ip_to_domain', {}), time_passed)
                self.ns_records = self._restore_from_serialized(
                    data.get('ns_records', {}), time_passed)

        except FileNotFoundError:
            pass
        except (json.JSONDecodeError, IOError) as e:
            print(f"[WARNING] Ошибка загрузки кэша: {e}")

    # Вспомогательные методы
    @staticmethod
    def _add_to_dict(
            target_dict: Dict[str, Dict[str, Tuple[float, int]]],
            key: str,
            value: str,
            expire_time: float,
            ttl: int
    ) -> None:
        """Добавляет запись в словарь кэша."""
        if key not in target_dict:
            target_dict[key] = {}
        target_dict[key][value] = (expire_time, ttl)

    @staticmethod
    def _get_valid_entries(
            source_dict: Dict[str, Dict[str, Tuple[float, int]]],
            key: str
    ) -> Optional[List[str]]:
        """Возвращает актуальные записи по ключу."""
        if key not in source_dict:
            return None

        current_time = time.time()
        valid_entries = [
            entry for entry, (expire, _) in source_dict[key].items()
            if expire > current_time
        ]

        return valid_entries if valid_entries else None

    @staticmethod
    def _cleanup_dict(
            target_dict: Dict[str, Dict[str, Tuple[float, int]]],
            current_time: float
    ) -> None:
        """Очищает словарь от устаревших записей."""
        for key in list(target_dict.keys()):
            target_dict[key] = {
                k: v for k, v in target_dict[key].items()
                if v[0] > current_time
            }
            if not target_dict[key]:
                del target_dict[key]

    @staticmethod
    def _prepare_for_serialization(
            source_dict: Dict[str, Dict[str, Tuple[float, int]]]
    ) -> Dict[str, Dict[str, List[float]]]:
        """Подготавливает данные для сериализации."""
        return {
            k: {kk: list(vv) for kk, vv in v.items()}
            for k, v in source_dict.items()
        }

    @staticmethod
    def _restore_from_serialized(
            serialized: Dict[str, Dict[str, List[float]]],
            time_passed: float
    ) -> Dict[str, Dict[str, Tuple[float, int]]]:
        """Восстанавливает данные после десериализации."""
        restored = {}
        current_time = time.time()

        for key, entries in serialized.items():
            restored[key] = {}
            for entry, (expire, ttl) in entries.items():
                new_expire = float(expire) - time_passed
                if new_expire > current_time:
                    restored[key][entry] = (new_expire, int(ttl))

        return restored