package com.example.ib.service;

import com.example.ib.crypto.Gost34112012Hasher;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;

@Service
public class FileHashService {
    private static final long MIN_SIZE_BYTES = 1024;
    private final Gost34112012Hasher hasher;

    public FileHashService(Gost34112012Hasher hasher) {
        this.hasher = hasher;
    }

    public String computeHash(MultipartFile file) throws IOException {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("Выберите файл для вычисления хэша.");
        }
        if (file.getSize() < MIN_SIZE_BYTES) {
            throw new IllegalArgumentException("Размер файла должен быть не менее 1 КБ.");
        }
        try (InputStream inputStream = file.getInputStream()) {
            return hasher.digestHex(inputStream);
        }
    }

    public long getMinSizeBytes() {
        return MIN_SIZE_BYTES;
    }
}
