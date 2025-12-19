package com.example.ib.service;

import com.example.ib.crypto.MagmaCipher;
import com.example.ib.crypto.MagmaCtrCipher;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

@Service
public class MagmaFileCipherService {

    private static final long MIN_SIZE_BYTES = 1024;

    private final MagmaCtrCipher magmaCtrCipher;

    public MagmaFileCipherService(MagmaCtrCipher magmaCtrCipher) {
        this.magmaCtrCipher = magmaCtrCipher;
    }

    public ProcessedFile process(
            MultipartFile dataFile,
            MultipartFile keyFile,
            String keyHex,
            String counterHex,
            CipherMode mode,
            String requestedName) throws IOException {

        if (dataFile == null || dataFile.isEmpty()) {
            throw new IllegalArgumentException("Выберите исходный файл.");
        }
        if (dataFile.getSize() < MIN_SIZE_BYTES) {
            throw new IllegalArgumentException("Размер файла должен быть не менее 1 КБ.");
        }
        byte[] key = resolveKey(keyHex, keyFile);
        long counter = parseCounter(counterHex);

        byte[] input = dataFile.getBytes();
        byte[] output = magmaCtrCipher.process(input, key, counter);

        String outputName = selectOutputName(dataFile.getOriginalFilename(), requestedName, mode);
        return new ProcessedFile(outputName, output);
    }

    public long getMinSizeBytes() {
        return MIN_SIZE_BYTES;
    }

    private byte[] resolveKey(String keyHex, MultipartFile keyFile) throws IOException {
        if (keyFile != null && !keyFile.isEmpty()) {
            byte[] content = keyFile.getBytes();
            if (content.length == MagmaCipher.KEY_SIZE) { // двоичный ключ
                return content;
            }
            String hexFromFile = new String(content, StandardCharsets.UTF_8);
            return parseHexKey(hexFromFile);
        }

        if (keyHex == null || keyHex.isBlank()) {
            throw new IllegalArgumentException("Необходимо задать 256-битный ключ в hex или загрузить файл с ключом.");
        }
        return parseHexKey(keyHex);
    }

    private byte[] parseHexKey(String hexString) {
        String normalized = normalizeHex(hexString);
        if (normalized.length() != MagmaCipher.KEY_SIZE * 2) {
            throw new IllegalArgumentException("Ключ должен содержать 64 шестнадцатеричных символа (256 бит).");
        }
        byte[] key = new byte[MagmaCipher.KEY_SIZE];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) Integer.parseInt(normalized.substring(i * 2, i * 2 + 2), 16);
        }
        return key;
    }

    private long parseCounter(String counterHex) {
        if (counterHex == null || counterHex.isBlank()) {
            throw new IllegalArgumentException("Введите начальное значение счётчика (64 бита, hex).");
        }
        String normalized = normalizeHex(counterHex);
        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("Счётчик должен быть задан шестнадцатеричными символами.");
        }
        if (normalized.length() > 16) {
            throw new IllegalArgumentException("Счётчик не должен превышать 64 бита (16 hex-символов).");
        }
        // допускаем укороченную запись, дополняем ведущими нулями
        String padded = String.format("%16s", normalized).replace(' ', '0');
        try {
            return Long.parseUnsignedLong(padded, 16);
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("Некорректное значение счётчика. Используйте hex-цифры 0-9, A-F.");
        }
    }

    private String normalizeHex(String value) {
        return value.replaceAll("[^0-9A-Fa-f]", "").toUpperCase();
    }

    private String selectOutputName(String sourceName, String requestedName, CipherMode mode) {
        String safeRequested = sanitizeFileName(requestedName);
        if (!safeRequested.isBlank()) {
            return safeRequested;
        }
        String base = sanitizeFileName(sourceName);
        if (base.isBlank()) {
            base = "data";
        }
        if (mode == CipherMode.ENCRYPT) {
            return base + ".gost";
        }
        // DECRYPT: попытка восстановить исходное имя
        String lowered = base.toLowerCase();
        if (lowered.endsWith(".gost")) {
            String trimmed = base.substring(0, base.length() - 5);
            if (!trimmed.isBlank()) {
                return trimmed;
            }
        }
        if (lowered.endsWith(".bin")) {
            String trimmed = base.substring(0, base.length() - 4);
            if (!trimmed.isBlank()) {
                return trimmed;
            }
        }
        return base + ".plain";
    }

    private String sanitizeFileName(String name) {
        if (name == null) {
            return "";
        }
        return Path.of(name).getFileName().toString().replaceAll("[\\\\/:*?\"<>|]", "").trim();
    }

    public enum CipherMode {
        ENCRYPT, DECRYPT;

        public static CipherMode fromString(String value) {
            if (value == null) {
                throw new IllegalArgumentException("Не указан режим работы (encrypt/decrypt).");
            }
            return switch (value.toLowerCase()) {
                case "encrypt" -> ENCRYPT;
                case "decrypt" -> DECRYPT;
                default -> throw new IllegalArgumentException("Некорректный режим. Используйте encrypt или decrypt.");
            };
        }
    }

    public record ProcessedFile(String fileName, byte[] content) {
    }
}
