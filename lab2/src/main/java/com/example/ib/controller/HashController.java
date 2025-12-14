package com.example.ib.controller;

import com.example.ib.service.FileHashService;
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
public class HashController {

    private final FileHashService fileHashService;

    public HashController(FileHashService fileHashService) {
        this.fileHashService = fileHashService;
    }

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("minFileSize", fileHashService.getMinSizeBytes());
        return "index";
    }

    @PostMapping(value = "/hash", consumes = "multipart/form-data")
    @ResponseBody
    public ResponseEntity<Map<String, String>> computeHash(@RequestParam("file") MultipartFile file) {
        try {
            String hash = fileHashService.computeHash(file);
            return ResponseEntity.ok(Map.of("hash", hash));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (IOException e) {
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", "Не удалось обработать файл. Повторите попытку позже."));
        }
    }
}
