const API = "http://127.0.0.1:8000/scan";
const recent = {}; // tabId -> {url, time}

function shouldSkip(url) {
  return !url || !url.startsWith("http") ||
         url.startsWith("http://127.0.0.1") ||
         url.startsWith("http://localhost");
}

async function scan(tabId, url) {
  if (shouldSkip(url)) {
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }
  // skip if the same tab+URL was scanned in the last 10 seconds
  const now = Date.now();
  const last = recent[tabId];
  if (last && last.url === url && now - last.time < 10000) return;
  recent[tabId] = { url, time: now };

  try {
    const res = await fetch(API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    const map = {
      Safe:       { text: "OK", color: "#2e9e4f" },
      Suspicious: { text: "!",  color: "#e0a100" },
      Dangerous:  { text: "X",  color: "#d6336c" }
    };
    const b = map[data.verdict] || { text: "?", color: "#888888" };

    if (data.verdict === "Dangerous") {
      try {
        await chrome.scripting.executeScript({
          target: { tabId },
          files: ["warning.js"]
        });
        chrome.tabs.sendMessage(tabId, { type: "SHOW_WARNING", data });
      } catch (e) {}
    }

    chrome.action.setBadgeText({ tabId, text: b.text });
    chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
  } catch (e) {
    chrome.action.setBadgeText({ tabId, text: "?" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#888888" });
  }
}

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === "complete") scan(tabId, tab.url);
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const tab = await chrome.tabs.get(tabId);
  scan(tabId, tab.url);
});