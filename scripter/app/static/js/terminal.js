(function () {
    var page = document.querySelector(".terminal-page");
    if (!page || typeof io !== "function") {
        return;
    }

    var csrfToken = page.getAttribute("data-csrf-token");
    var forms = document.querySelectorAll(".terminal-input-form");
    var executionIds = Array.prototype.slice.call(forms)
        .map(function (form) {
            return parseInt(form.getAttribute("data-execution-id"), 10);
        })
        .filter(function (id) {
            return Number.isInteger(id) && id > 0;
        });

    if (!csrfToken || executionIds.length === 0) {
        return;
    }

    function setStatus(id, status) {
        var badge = document.getElementById("status-" + id);
        if (!badge) {
            return;
        }
        var label = "En cours";
        if (status === "success") {
            label = "Terminé";
        } else if (status === "error") {
            label = "Erreur";
        } else if (status === "timeout") {
            label = "Timeout";
        }
        badge.textContent = label;
        badge.className = "badge " + status;
        badge.setAttribute("data-status", status);
    }

    function appendOutput(id, data) {
        var el = document.getElementById("output-" + id);
        if (!el || typeof data !== "string") {
            return;
        }
        el.textContent += data;
        el.scrollTop = el.scrollHeight;
    }

    var socket = io({
        transports: ["websocket", "polling"]
    });

    socket.on("connect", function () {
        executionIds.forEach(function (id) {
            socket.emit("join", { execution_id: id, csrf: csrfToken });
        });
    });

    socket.on("output", function (msg) {
        if (msg && Number.isInteger(Number(msg.id))) {
            appendOutput(Number(msg.id), msg.data);
        }
    });

    socket.on("status", function (msg) {
        if (msg && Number.isInteger(Number(msg.id))) {
            setStatus(Number(msg.id), msg.status);
        }
    });

    forms.forEach(function (form) {
        form.addEventListener("submit", function (evt) {
            evt.preventDefault();
            var id = parseInt(form.getAttribute("data-execution-id"), 10);
            var input = document.getElementById("input-" + id);
            if (!input || !Number.isInteger(id) || id <= 0) {
                return;
            }
            socket.emit("terminal_input", {
                execution_id: id,
                text: input.value + "\n",
                csrf: csrfToken
            });
            input.value = "";
        });
    });
})();
