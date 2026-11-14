const API = "http://127.0.0.1:8000";

function fillList(el, items) {
  el.innerHTML = "";
  items.forEach(r => {
    const li = document.createElement("li");
    li.textContent = r;
    el.appendChild(li);
  });
}

async function scanPage() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  document.getElementById("url").textContent = tab.url;
  const v = document.getElementById("verdict");

  if (!tab.url.startsWith("http")) {
    v.textContent = "Not a web page";
    return;
  }
  try {
    const res = await fetch(API + "/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: tab.url })
    });
    const data = await res.json();
    v.textContent = data.verdict;
    v.className = "box " + data.verdict;
    fillList(document.getElementById("reasons"), data.reasons);
  } catch (e) {
    v.textContent = "API not running";
  }
}

async function checkMessage() {
  const text = document.getElementById("msg").value.trim();
  if (!text) return;
  const v = document.getElementById("msgVerdict");
  v.style.display = "block";
  v.className = "box";
  v.textContent = "Checking...";
  try {
    const res = await fetch(API + "/scan-text", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text })
    });
    const data = await res.json();
    v.textContent = data.verdict;
    v.className = "box " + data.verdict;
    fillList(document.getElementById("msgReasons"), data.reasons);
  } catch (e) {
    v.textContent = "API not running";
  }
}

document.getElementById("checkMsg").addEventListener("click", checkMessage);
scanPage();