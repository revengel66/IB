document.addEventListener('DOMContentLoaded', () => {
    initHashForm();
});

function initHashForm() {
    const form = document.getElementById('hashForm');
    if (!form) {
        return;
    }

    const fileInput = document.getElementById('fileInput');
    const hashOutput = document.getElementById('hashOutput');
    const progressWrapper = document.getElementById('hashProgressWrapper');
    const progressBar = document.getElementById('hashProgressBar');
    const messageBox = document.getElementById('hashMessage');
    const cancelButton = document.getElementById('cancelHashButton');
    const submitButton = document.getElementById('hashButton');
    const minSize = Number(fileInput?.dataset?.minSize || '1024');

    let currentRequest = null;

    form.addEventListener('submit', (event) => {
        event.preventDefault();
        if (currentRequest) {
            return;
        }
        const file = fileInput.files && fileInput.files[0];
        if (!file) {
            showMessage('Выберите файл для вычисления хэша.', 'error');
            return;
        }
        if (file.size < minSize) {
            showMessage('Размер файла должен быть не менее 1 КБ.', 'error');
            return;
        }
        hashOutput.value = '';
        showMessage('', 'success');

        const formData = new FormData(form);
        const xhr = new XMLHttpRequest();
        currentRequest = xhr;
        xhr.responseType = 'json';
        xhr.open('POST', form.action, true);

        xhr.upload.addEventListener('progress', (event) => {
            if (event.lengthComputable) {
                const percent = Math.round((event.loaded / event.total) * 100);
                updateProgress(percent);
            }
        });

        xhr.addEventListener('loadstart', () => {
            setWorkingState(true);
            updateProgress(0);
            showMessage('Файл загружается и обрабатывается...', 'info');
        });

        xhr.addEventListener('abort', () => {
            showMessage('Вычисление отменено пользователем.', 'info');
        });

        xhr.addEventListener('error', () => {
            showMessage('Произошла ошибка при отправке файла.', 'error');
        });

        xhr.addEventListener('loadend', () => {
            finalizeRequest();
        });

        xhr.onreadystatechange = () => {
            if (xhr.readyState !== XMLHttpRequest.DONE) {
                return;
            }
            if (xhr.status >= 200 && xhr.status < 300 && xhr.response && xhr.response.hash) {
                hashOutput.value = xhr.response.hash;
                updateProgress(100);
                showMessage('Хэш успешно вычислен.', 'success');
            } else if (xhr.status !== 0) {
                const errorMessage = xhr.response && xhr.response.error
                    ? xhr.response.error
                    : 'Не удалось вычислить хэш. Повторите попытку позже.';
                showMessage(errorMessage, 'error');
            }
        };

        xhr.send(formData);
    });

    cancelButton.addEventListener('click', () => {
        if (!currentRequest) {
            return;
        }
        currentRequest.abort();
        currentRequest = null;
        finalizeRequest();
    });

    function setWorkingState(isWorking) {
        progressWrapper.classList.toggle('d-none', !isWorking);
        cancelButton.classList.toggle('d-none', !isWorking);
        submitButton.disabled = isWorking;
        fileInput.disabled = isWorking;
    }

    function finalizeRequest() {
        setWorkingState(false);
        currentRequest = null;
        setTimeout(() => updateProgress(0), 300);
    }

    function updateProgress(value) {
        const percent = Math.min(100, Math.max(0, Math.round(value)));
        progressBar.style.width = percent + '%';
        progressBar.setAttribute('aria-valuenow', percent.toString());
        progressBar.textContent = percent + '%';
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

        messageBox.textContent = text;
        const className = type === 'success'
            ? 'alert-success'
            : type === 'info'
                ? 'alert-info'
                : 'alert-danger';
        messageBox.classList.remove('d-none');
        messageBox.classList.add(className);
    }
}
