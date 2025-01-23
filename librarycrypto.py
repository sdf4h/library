# simplecrypto.py

import os
import json
import hmac
import hashlib
from PIL import Image  # Для стеганографии
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend

class SimpleCrypto:
    def __init__(self, key_storage_file='key_storage.json'):
        self.key_storage_file = key_storage_file
        self.key_storage = self._load_key_storage()

    def _load_key_storage(self):
        if os.path.exists(self.key_storage_file):
            with open(self.key_storage_file, 'r') as file:
                return json.load(file)
        else:
            return {}

    def _save_key_storage(self):
        with open(self.key_storage_file, 'w') as file:
            json.dump(self.key_storage, file)

    # ------------------------------------
    # Управление ключами
    # ------------------------------------

    def generate_symmetric_key(self, algorithm='AES', key_size=256):
        """
        Генерирует симметричный ключ заданного размера.
        """
        if algorithm.upper() == 'AES':
            if key_size not in (128, 192, 256):
                raise ValueError("Для AES размер ключа должен быть 128, 192 или 256 бит.")
            key = os.urandom(key_size // 8)
        else:
            raise ValueError("Неподдерживаемый алгоритм.")
        return key

    def store_key(self, alias, key):
        """
        Сохраняет ключ по указанному псевдониму.
        """
        self.key_storage[alias] = key.hex()
        self._save_key_storage()

    def get_key(self, alias):
        """
        Извлекает ключ по указанному псевдониму.
        """
        key_hex = self.key_storage.get(alias)
        if key_hex:
            return bytes.fromhex(key_hex)
        else:
            raise KeyError(f"Ключ с псевдонимом '{alias}' не найден.")

    # ------------------------------------
    # Симметричное шифрование
    # ------------------------------------

    def encrypt_symmetric(self, data, key, algorithm='AES', mode='CBC'):
        """
        Шифрует данные симметричным алгоритмом.
        """
        if algorithm.upper() == 'AES':
            if mode.upper() == 'CBC':
                # Инициализационный вектор (IV) должен быть случайным и уникальным
                iv = os.urandom(16)
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            else:
                raise ValueError("Неподдерживаемый режим шифрования.")
        else:
            raise ValueError("Неподдерживаемый алгоритм шифрования.")

        # Выравнивание данных до блока
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Возвращаем IV и зашифрованные данные
        return iv + encrypted_data

    def decrypt_symmetric(self, encrypted_data, key, algorithm='AES', mode='CBC'):
        """
        Расшифровывает данные симметричным алгоритмом.
        """
        if algorithm.upper() == 'AES':
            if mode.upper() == 'CBC':
                iv = encrypted_data[:16]
                encrypted_data = encrypted_data[16:]
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            else:
                raise ValueError("Неподдерживаемый режим шифрования.")
        else:
            raise ValueError("Неподдерживаемый алгоритм шифрования.")

        decryptor = cipher.decryptor()
      
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Удаляем выравнивание
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        return data

    # ------------------------------------
    # Стеганография
    # ------------------------------------

    def hide_data_in_image(self, image_path, data, output_path):
        """
        Скрывает данные внутри изображения с использованием LSB стеганографии.
        """
        img = Image.open(image_path)
        encoded_img = img.copy()
        width, height = img.size
        max_capacity = width * height * 3 // 8  # Максимальное количество байт, которые можно скрыть

        if len(data) > max_capacity:
            raise ValueError("Данные слишком велики для выбранного изображения.")

        data_bits = ''.join(format(byte, '08b') for byte in data)
        data_len = len(data_bits)
        data_index = 0

        for y in range(height):
            for x in range(width):
                if data_index < data_len:
                    pixel = list(img.getpixel((x, y)))
                    for n in range(3):  # Для каждого канала RGB
                        if data_index < data_len:
                            # Заменяем младший бит каждого канала на бит данных
                            pixel[n] = pixel[n] & ~1 | int(data_bits[data_index])
                            data_index += 1
                    encoded_img.putpixel((x, y), tuple(pixel))
                else:
                    break
            else:
                continue
            break

        encoded_img.save(output_path)
        return output_path

    def extract_data_from_image(self, image_path):
        """
        Извлекает скрытые данные из изображения.
        """
        img = Image.open(image_path)
        width, height = img.size

        data_bits = ''
        for y in range(height):
            for x in range(width):
                pixel = img.getpixel((x, y))
                for n in range(3):  # Для каждого канала RGB
                    data_bits += str(pixel[n] & 1)

        # Группируем биты по 8 для получения байтов
        all_bytes = [data_bits[i: i+8] for i in range(0, len(data_bits), 8)]
        data = bytearray()

        for byte in all_bytes:
            data.append(int(byte, 2))
            # Проверяем на конец данных
            if data[-1:] == b'\x00':  # Используем нулевой байт как терминатор
                break

        return bytes(data[:-1])  # Возвращаем данные без терминатора

    # ------------------------------------
    # HMAC
    # ------------------------------------

    def create_hmac(self, data, key, algorithm='SHA256'):
        """
        Создает HMAC для заданных данных и ключа.
        """
        if algorithm.upper() == 'SHA256':
            hash_func = hashes.SHA256()
        elif algorithm.upper() == 'SHA512':
            hash_func = hashes.SHA512()
        else:
            raise ValueError("Неподдерживаемый алгоритм хеширования.")
        h = HMAC(key, hash_func, backend=default_backend())
        h.update(data)
        return h.finalize()

    def verify_hmac(self, data, key, mac, algorithm='SHA256'):
        """
        Проверяет HMAC для заданных данных и ключа.
        """
        if algorithm.upper() == 'SHA256':
            hash_func = hashes.SHA256()
        elif algorithm.upper() == 'SHA512':
            hash_func = hashes.SHA512()
        else:
            raise ValueError("Неподдерживаемый алгоритм хеширования.")
        h = HMAC(key, hash_func, backend=default_backend())
        h.update(data)
        try:
            h.verify(mac)
            return True
        except Exception:
            return False
