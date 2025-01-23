from simplecrypto import SimpleCrypto

# Инициализируем библиотеку
crypto = SimpleCrypto()

# Генерируем симметричный ключ и сохраняем его
key = crypto.generate_symmetric_key(algorithm='AES', key_size=256)
crypto.store_key('my_aes_key', key)

# Исходные данные
data = b'Секретное сообщение'

# Получаем ключ по псевдониму
key = crypto.get_key('my_aes_key')

# Шифруем данные симметрично
encrypted_data = crypto.encrypt_symmetric(data, key, algorithm='AES', mode='CBC')

# Добавляем нулевой байт как терминатор перед скрытием данных
encrypted_data += b'\x00'

# Скрываем данные в изображении
original_image = 'original_image.png'  # Путь к исходному изображению
stego_image = 'stego_image.png'        # Путь для сохранения изображения с скрытыми данными
crypto.hide_data_in_image(original_image, encrypted_data, stego_image)
print(f"Данные скрыты в изображении {stego_image}")

# Извлекаем данные из изображения
extracted_data = crypto.extract_data_from_image(stego_image)

# Удаляем нулевой байт терминатора
extracted_data = extracted_data.rstrip(b'\x00')

# Дешифруем данные
decrypted_data = crypto.decrypt_symmetric(extracted_data, key, algorithm='AES', mode='CBC')
print("Расшифрованные данные:", decrypted_data.decode('utf-8'))
