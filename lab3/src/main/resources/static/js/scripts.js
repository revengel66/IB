document.addEventListener('DOMContentLoaded', () => {
    initCipherForm();
});

function initCipherForm() {
    const form = document.getElementById('cipherForm');
    if (!form) {
        return;
    }

    const fileInput = document.getElementById('fileInput');
    const keyHexInput = document.getElementById('keyHex');
    const keyFileInput = document.getElementById('keyFile');
    const counterInput = document.getElementById('counter');
    const messageBox = document.getElementById('cipherMessage');
    const spinner = document.getElementById('cipherSpinner');
    const statusText = document.getElementById('statusText');
    const submitButton = document.getElementById('cipherButton');
    const downloadHint = document.getElementById('downloadHint');
    const downloadLink = document.getElementById('downloadLink');
    const outputNameInput = document.getElementById('outputName');
    const minSize = Number(fileInput?.dataset?.minSize || '1024');

    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        hideDownloadHint();

        const file = fileInput.files && fileInput.files[0];
        if (!file) {
            showMessage('Выберите файл для шифрования или расшифрования.', 'error');
            return;
        }
        if (file.size < minSize) {
            showMessage('Размер файла должен быть не менее 1 КБ.', 'error');
            return;
        }
        if (!keyHexInput.value.trim() && (!keyFileInput.files || keyFileInput.files.length === 0)) {
            showMessage('Задайте 256-битный ключ вручную или загрузите файл с ключом.', 'error');
            return;
        }
        if (!counterInput.value.trim()) {
            showMessage('Введите начальное значение счётчика (64 бита, hex).', 'error');
            return;
        }

        const formData = new FormData(form);

        try {
            setWorking(true);
            setStatus('Формируется гамма по ГОСТ Р 34.13-2018...');

            const response = await fetch(form.action, {
                method: 'POST',
                body: formData,
            });

            const contentType = response.headers.get('content-type') || '';
            if (!response.ok) {
                const errorText = await extractError(response, contentType);
                showMessage(errorText, 'error');
                return;
            }

            const blob = await response.blob();
            const disposition = response.headers.get('content-disposition') || '';
            const filename = chooseFileName(disposition);

            triggerDownload(blob, filename, downloadLink);
            downloadHint.classList.remove('d-none');
            showMessage('Файл сформирован. Скачивание началось автоматически.', 'success');
            setStatus('Гамма построена шифрованием счётчика «Магмой».');
        } catch (error) {
            showMessage('Не удалось выполнить запрос: ' + error.message, 'error');
        } finally {
            setWorking(false);
        }
    });

    function parseFileName(disposition) {
        if (!disposition) {
            return '';
        }
        // filename* (RFC 5987) с кодировкой UTF-8
        const starMatch = /filename\*=([^;]+)/i.exec(disposition);
        if (starMatch) {
            const value = starMatch[1].trim();
            const withoutPrefix = value.replace(/^UTF-8''/i, '').replace(/\"/g, '');
            try {
                return decodeURIComponent(withoutPrefix);
            } catch (e) {
                return withoutPrefix;
            }
        }
        const match = /filename=([^;]+)/i.exec(disposition);
        if (!match) {
            const encodedWord = parseEncodedWord(disposition);
            return encodedWord;
        }
        return match[1].replace(/\"/g, '').trim();
    }

    function chooseFileName(disposition) {
        const fromHeader = parseFileName(disposition);
        if (fromHeader) {
            return fromHeader;
        }
        const manual = (outputNameInput?.value || '').trim();
        if (manual) {
            return manual;
        }
        const source = fileInput?.files?.[0]?.name || 'result.bin';
        return deriveFromSource(source);
    }

    function deriveFromSource(source) {
        const lowered = source.toLowerCase();
        if (lowered.endsWith('.gost')) {
            return source.slice(0, -5) || 'result.bin';
        }
        if (lowered.endsWith('.bin')) {
            return source.slice(0, -4) || 'result.bin';
        }
        return source || 'result.bin';
    }

    // Декодирование формата =?UTF-8?Q?...?= (квотированное слово)
    function parseEncodedWord(headerValue) {
        const encodedMatch = /=\?utf-8\?(q|b)\?([^?]+)\?=/i.exec(headerValue);
        if (!encodedMatch) {
            return '';
        }
        const type = encodedMatch[1].toLowerCase();
        const data = encodedMatch[2];
        if (type === 'b') {
            try {
                return atob(data);
            } catch (e) {
                return data;
            }
        }
        // Q-encoding
        return decodeQ(data);
    }

    function decodeQ(data) {
        let text = data.replace(/_/g, ' ');
        const bytes = [];
        for (let i = 0; i < text.length; i++) {
            const ch = text[i];
            if (ch === '=' && i + 2 < text.length && /[0-9A-Fa-f]{2}/.test(text.substring(i + 1, i + 3))) {
                bytes.push(parseInt(text.substring(i + 1, i + 3), 16));
                i += 2;
            } else {
                bytes.push(ch.charCodeAt(0));
            }
        }
        try {
            return new TextDecoder('utf-8').decode(new Uint8Array(bytes));
        } catch (e) {
            return text;
        }
    }

    async function extractError(response, contentType) {
        if (contentType.includes('application/json')) {
            try {
                const json = await response.json();
                return json?.error || 'Не удалось обработать файл.';
            } catch (e) {
                return 'Не удалось прочитать ответ от сервера.';
            }
        }
        return 'Ошибка сервера: ' + response.status;
    }

    function triggerDownload(blob, filename, fallbackLink) {
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = filename;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();

        if (fallbackLink) {
            fallbackLink.href = url;
            fallbackLink.download = filename;
        }

        setTimeout(() => URL.revokeObjectURL(url), 60_000);
    }

    function setWorking(isWorking) {
        spinner.classList.toggle('d-none', !isWorking);
        submitButton.disabled = isWorking;
        fileInput.disabled = isWorking;
        keyFileInput.disabled = isWorking;
        keyHexInput.disabled = isWorking;
    }

    function showMessage(text, type) {
        if (!messageBox) {
            return;
        }
        messageBox.classList.remove('alert-success', 'alert-danger', 'alert-info');
        if (!text) {
            messageBox.classList.add('d-none');
            messageBox.textContent = '';
            return;
        }
        const className = type === 'success'
            ? 'alert-success'
            : type === 'info'
                ? 'alert-info'
                : 'alert-danger';
        messageBox.classList.remove('d-none');
        messageBox.classList.add(className);
        messageBox.textContent = text;
    }

    function setStatus(text) {
        if (statusText) {
            statusText.textContent = text;
        }
    }

    function hideDownloadHint() {
        if (downloadHint) {
            downloadHint.classList.add('d-none');
            downloadLink.removeAttribute('href');
            downloadLink.removeAttribute('download');
        }
    }
}
