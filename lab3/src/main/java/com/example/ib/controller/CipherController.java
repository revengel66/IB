package com.example.ib.controller;

import com.example.ib.service.MagmaFileCipherService;
import com.example.ib.service.MagmaFileCipherService.CipherMode;
import com.example.ib.service.MagmaFileCipherService.ProcessedFile;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Map;

@Controller
public class CipherController {

    private final MagmaFileCipherService cipherService;

    public CipherController(MagmaFileCipherService cipherService) {
        this.cipherService = cipherService;
    }

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("minFileSize", cipherService.getMinSizeBytes());
        return "index";
    }

    @PostMapping(value = "/cipher", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @ResponseBody
    public ResponseEntity<?> process(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "keyFile", required = false) MultipartFile keyFile,
            @RequestParam(value = "keyHex", required = false) String keyHex,
            @RequestParam("counter") String counterHex,
            @RequestParam("mode") String mode,
            @RequestParam(value = "outputName", required = false) String outputName) {
        try {
            CipherMode cipherMode = CipherMode.fromString(mode);
            ProcessedFile processed = cipherService.process(file, keyFile, keyHex, counterHex, cipherMode, outputName);
            String cd = buildContentDisposition(processed.fileName());
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .header(HttpHeaders.CONTENT_DISPOSITION, cd)
                    .body(processed.content());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (IOException e) {
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", "Не удалось обработать файл. Повторите попытку позже."));
        }
    }

    /**
     * Строит заголовок Content-Disposition с filename и filename* (RFC 5987) для корректной
     * передачи русских имен файлов.
     */
    private String buildContentDisposition(String fileName) {
        String safeQuoted = quoteValue(fileName);
        String encoded = rfc5987Encode(fileName);
        return "attachment; filename=\"" + safeQuoted + "\"; filename*=UTF-8''" + encoded;
    }

    private String quoteValue(String value) {
        // Убираем управляющие символы и кавычки, остальные (в т.ч. кириллица) оставляем.
        String cleaned = value.replaceAll("[\\r\\n\"]", "_");
        return cleaned;
    }

    private String rfc5987Encode(String value) {
        StringBuilder sb = new StringBuilder();
        for (char ch : value.toCharArray()) {
            if (isAttrChar(ch)) {
                sb.append(ch);
            } else {
                byte[] bytes = String.valueOf(ch).getBytes(java.nio.charset.StandardCharsets.UTF_8);
                for (byte b : bytes) {
                    sb.append('%');
                    String hex = Integer.toHexString(b & 0xFF).toUpperCase();
                    if (hex.length() == 1) {
                        sb.append('0');
                    }
                    sb.append(hex);
                }
            }
        }
        return sb.toString();
    }

    // Разрешенные символы из RFC 5987 (attr-char)
    private boolean isAttrChar(char ch) {
        return (ch >= '0' && ch <= '9')
                || (ch >= 'a' && ch <= 'z')
                || (ch >= 'A' && ch <= 'Z')
                || ch == '!' || ch == '#' || ch == '$' || ch == '&' || ch == '+' || ch == '-'
                || ch == '.' || ch == '^' || ch == '_' || ch == '`' || ch == '|' || ch == '~';
    }
}
