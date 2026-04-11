const API_BASE = window.location.origin;
const token = localStorage.getItem("token");
const username = localStorage.getItem("username");

let currentUserId = null;
let socket = null;
let pingInterval = null;

if (!token) {
  window.location.href = "login.html";
}

document.addEventListener("DOMContentLoaded", async () => {
  const currentUser = document.getElementById("currentUser");
  if (currentUser) currentUser.textContent = username || "Unknown";

  await loadCurrentUser();
  await loadInbox();
  connectWebSocket();
});

function setStatus(message, isError = false) {
  const status = document.getElementById("status");
  if (!status) return;
  status.textContent = message;
  status.style.color = isError ? "#f87171" : "#9ca3af";
}

function logout() {
  if (socket) socket.close();
  if (pingInterval) clearInterval(pingInterval);
  localStorage.removeItem("token");
  localStorage.removeItem("username");
  window.location.href = "login.html";
}

async function apiFetch(url, options = {}) {
  const headers = {
    "Authorization": "Bearer " + token,
    ...(options.headers || {})
  };

  const res = await fetch(url, { ...options, headers });
  let data = null;

  try {
    data = await res.json();
  } catch {
    data = null;
  }

  if (!res.ok) {
    throw new Error(data?.detail || "Request failed");
  }

  return data;
}

async function loadCurrentUser() {
  try {
    const data = await apiFetch(`${API_BASE}/users/me/id`);
    currentUserId = data.id;
  } catch (err) {
    setStatus(err.message, true);
  }
}

function connectWebSocket() {
  if (!currentUserId) return;

  const wsProtocol = window.location.protocol === "https:" ? "wss" : "ws";
  socket = new WebSocket(`${wsProtocol}://${window.location.host}/ws/${currentUserId}`);

  socket.onopen = () => {
    setStatus("Realtime connection active");

    if (pingInterval) clearInterval(pingInterval);
    pingInterval = setInterval(() => {
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send("ping");
      }
    }, 20000);
  };

  socket.onmessage = async (event) => {
    try {
      const data = JSON.parse(event.data);

      if (data.type === "new_message") {
        setStatus(`New encrypted message from ${data.sender_username}`);
        await loadInbox();
      }

      if (data.type === "message_read") {
        setStatus("Message opened. Burn countdown started.");
      }
    } catch {
      // ignore non-json websocket messages like ping/pong noise
    }
  };

  socket.onclose = (event) => {
    console.log("WebSocket closed:", event);
    setStatus("Realtime disconnected. Retrying...");
    if (pingInterval) clearInterval(pingInterval);
    setTimeout(connectWebSocket, 3000);
  };

  socket.onerror = (event) => {
    console.error("WebSocket error:", event);
    setStatus("Realtime error", true);
  };
}

function toBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function fromBase64(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function deriveKeyFromPassphrase(passphrase, saltBytes) {
  const encoder = new TextEncoder();

  const baseKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: 250000,
      hash: "SHA-256"
    },
    baseKey,
    {
      name: "AES-GCM",
      length: 256
    },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptMessage(plaintext, passphrase) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const key = await deriveKeyFromPassphrase(passphrase, salt);

  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(plaintext)
  );

  return {
    ciphertext: toBase64(new Uint8Array(ciphertextBuffer)),
    iv: toBase64(iv),
    salt: toBase64(salt)
  };
}

async function decryptMessage(ciphertextB64, ivB64, saltB64, passphrase) {
  const decoder = new TextDecoder();
  const ciphertext = fromBase64(ciphertextB64);
  const iv = fromBase64(ivB64);
  const salt = fromBase64(saltB64);

  const key = await deriveKeyFromPassphrase(passphrase, salt);

  const plaintextBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext
  );

  return decoder.decode(plaintextBuffer);
}

async function loadInbox() {
  try {
    const data = await apiFetch(`${API_BASE}/messages/inbox`);
    const container = document.getElementById("messages");
    container.innerHTML = "";

    if (!Array.isArray(data) || data.length === 0) {
      container.innerHTML = `<div class="empty">No messages yet.</div>`;
      return;
    }

    data.forEach(msg => {
      const div = document.createElement("div");
      div.className = "message-card";
      div.dataset.messageId = msg.id;

      const burnInfo = msg.status === "burning" && msg.burn_at
        ? `<div class="meta burning">Burning until: ${new Date(msg.burn_at).toLocaleTimeString()}</div>`
        : `<div class="meta">Status: Encrypted message received</div>`;

      div.innerHTML = `
        <p><strong>From:</strong> ${msg.sender_username}</p>
        ${burnInfo}
        <button onclick="readMessage(${msg.id}, ${msg.burn_after_seconds}, this)">Open & Decrypt</button>
      `;

      container.appendChild(div);
    });
  } catch (err) {
    setStatus(err.message, true);
  }
}

async function sendMessage() {
  const to = document.getElementById("to").value.trim();
  const msg = document.getElementById("msg").value.trim();
  const burn = parseInt(document.getElementById("burn").value, 10);
  const sharedSecret = document.getElementById("sharedSecret").value;

  if (!to || !msg || !sharedSecret) {
    setStatus("Recipient, message, and shared secret are required", true);
    return;
  }

  try {
    const encrypted = await encryptMessage(msg, sharedSecret);

    await apiFetch(`${API_BASE}/messages`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        recipient_username: to,
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        salt: encrypted.salt,
        burn_after_seconds: burn
      })
    });

    document.getElementById("msg").value = "";
    setStatus("Encrypted message sent successfully");
  } catch (err) {
    setStatus(err.message, true);
  }
}

async function readMessage(id, burnSeconds, buttonEl) {
  const sharedSecret = prompt("Enter shared secret to decrypt this message:");
  if (!sharedSecret) {
    setStatus("Decryption canceled", true);
    return;
  }

  try {
    const inbox = await apiFetch(`${API_BASE}/messages/inbox`);
    const msg = inbox.find(item => item.id === id);

    if (!msg) {
      setStatus("Message not found", true);
      return;
    }

    const plaintext = await decryptMessage(
      msg.ciphertext,
      msg.iv,
      msg.salt,
      sharedSecret
    );

    const card = buttonEl.closest(".message-card");
    if (!card) return;

    const existingPlain = card.querySelector(".plaintext");
    if (existingPlain) existingPlain.remove();

    const plainDiv = document.createElement("div");
    plainDiv.className = "plaintext";
    plainDiv.innerHTML = `<strong>Decrypted message:</strong><br>${plaintext}`;
    card.appendChild(plainDiv);

    buttonEl.disabled = true;
    buttonEl.textContent = "Decrypted";

    await apiFetch(`${API_BASE}/messages/${id}/read`, {
      method: "POST"
    });

    setStatus(`Message decrypted. Burn timer started for ${burnSeconds} seconds.`);

    setTimeout(async () => {
      try {
        await fetch(`${API_BASE}/maintenance/cleanup`, { method: "POST" });
      } catch {}
      await loadInbox();
    }, (burnSeconds + 1) * 1000);

  } catch (err) {
    setStatus("Decrypt failed. Wrong secret or corrupted message.", true);
  }
}