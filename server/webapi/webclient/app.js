const STORAGE_PREFIX = 'openOscar.webClient';

const state = {
  apiKey: '',
  screenName: localStorage.getItem(`${STORAGE_PREFIX}.screenName`) || '',
  token: '',
  aimsid: '',
  lastSeqNum: 0,
  polling: false,
  pollController: null,
  contacts: new Map(),
  selectedContact: '',
  presenceState: 'online',
  history: {},
};

const $ = (id) => document.getElementById(id);
const elements = {
  status: $('connection-status'),
  logoutButton: $('logout-button'),
  loginPanel: $('login-panel'),
  clientPanel: $('client-panel'),
  loginForm: $('login-form'),
  loginButton: $('login-button'),
  apiKey: $('api-key'),
  screenName: $('screen-name'),
  password: $('password'),
  sessionSummary: $('session-summary'),
  presenceState: $('presence-state'),
  refreshContacts: $('refresh-contacts'),
  addContactForm: $('add-contact-form'),
  contactName: $('contact-name'),
  contactFilter: $('contact-filter'),
  contactList: $('contact-list'),
  chatTitle: $('chat-title'),
  chatSubtitle: $('chat-subtitle'),
  clearHistory: $('clear-history'),
  messages: $('messages'),
  messageForm: $('message-form'),
  messageText: $('message-text'),
  sendButton: $('send-button'),
  toast: $('toast'),
};

elements.screenName.value = state.screenName;
elements.loginForm.addEventListener('submit', login);
elements.logoutButton.addEventListener('click', logout);
elements.presenceState.addEventListener('change', updateOwnPresence);
elements.refreshContacts.addEventListener('click', () => refreshContacts(true).catch((error) => {
  showToast(`Не удалось обновить контакты: ${error.message}`, true);
}));
elements.addContactForm.addEventListener('submit', addContact);
elements.contactFilter.addEventListener('input', renderContacts);
elements.messageForm.addEventListener('submit', sendMessage);
elements.clearHistory.addEventListener('click', clearCurrentHistory);
window.addEventListener('beforeunload', () => stopPolling());

loadClientConfig().catch((error) => {
  setStatus('Клиент не настроен');
  showToast(error.message, true);
});
renderContacts();
renderConversation();

function setStatus(text) {
  elements.status.textContent = text;
}

function showToast(message, isError = false) {
  elements.toast.textContent = message;
  elements.toast.classList.toggle('error', isError);
  elements.toast.hidden = false;
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => {
    elements.toast.hidden = true;
  }, 4200);
}

function normalizeName(name) {
  return String(name || '').trim();
}

function contactKey(name) {
  return normalizeName(name).toLowerCase();
}

function historyKey() {
  return `${STORAGE_PREFIX}.history.${contactKey(state.screenName)}`;
}

function loadHistory() {
  if (!state.screenName) {
    state.history = {};
    return;
  }
  try {
    state.history = JSON.parse(localStorage.getItem(historyKey()) || '{}');
  } catch {
    state.history = {};
  }
}

function saveHistory() {
  if (state.screenName) {
    localStorage.setItem(historyKey(), JSON.stringify(state.history));
  }
}

function apiURL(path, params = {}) {
  const url = new URL(path, window.location.origin);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      url.searchParams.set(key, value);
    }
  }
  return url;
}

async function readAPIResponse(response) {
  const text = await response.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      throw new Error(`Неожиданный ответ сервера: ${text.slice(0, 180)}`);
    }
  }

  if (!response.ok) {
    throw new Error(payload?.response?.statusText || payload?.error || response.statusText);
  }

  const statusCode = payload?.response?.statusCode;
  if (statusCode && statusCode >= 400) {
    throw new Error(payload.response.statusText || `Ошибка API ${statusCode}`);
  }

  return payload;
}

async function postJSON(path, body) {
  const response = await fetch(apiURL(path), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return readAPIResponse(response);
}

async function getJSON(path, params) {
  const response = await fetch(apiURL(path, { f: 'json', ...params }));
  return readAPIResponse(response);
}

function responseData(payload) {
  return payload?.response?.data || {};
}

async function loadClientConfig() {
  const response = await fetch(apiURL('/client/config'));
  const payload = await readAPIResponse(response);
  state.apiKey = payload.apiKey || '';
  elements.apiKey.value = state.apiKey;
  if (!state.apiKey) {
    throw new Error('Встроенный Web-клиент не получил API ключ. Перезапустите WebAPI.');
  }
}

function contactFromBuddy(buddy) {
  const aimId = normalizeName(buddy?.aimId || buddy?.screenName || buddy?.displayId || buddy?.name || String(buddy || ''));
  if (!aimId) {
    return null;
  }
  return {
    aimId,
    displayId: buddy.displayId || aimId,
    state: buddy.state || 'offline',
    statusMsg: buddy.statusMsg || buddy.awayMsg || '',
    group: buddy.group || 'Buddies',
    onlineTime: buddy.onlineTime || 0,
  };
}

function upsertContact(contact) {
  if (!contact?.aimId) {
    return;
  }
  const key = contactKey(contact.aimId);
  const previous = state.contacts.get(key) || {};
  state.contacts.set(key, { ...previous, ...contact, aimId: previous.aimId || contact.aimId });
}

function contactStatus(contact) {
  return ['online', 'away', 'idle', 'dnd'].includes(contact?.state) ? contact.state : 'offline';
}

function statusLabel(status) {
  return status === 'online' ? 'в сети' : status === 'away' ? 'отошёл' : status === 'idle' ? 'неактивен' : 'не в сети';
}

function setSignedIn(data) {
  state.aimsid = data.aimsid;
  state.lastSeqNum = 0;
  state.presenceState = 'online';
  elements.presenceState.value = 'online';
  elements.loginPanel.hidden = true;
  elements.clientPanel.hidden = false;
  elements.sessionSummary.textContent = `${state.screenName} · в сети`;
  setStatus(`В сети: ${state.screenName}`);
  loadHistory();
  mergeBuddyGroups(data.events?.buddylist?.groups || data.myInfo?.buddylist?.groups || []);
  renderContacts();
  renderConversation();
}

function setSignedOut(reason = 'Ожидание входа') {
  stopPolling();
  state.token = '';
  state.aimsid = '';
  state.lastSeqNum = 0;
  state.presenceState = 'online';
  elements.loginPanel.hidden = false;
  elements.clientPanel.hidden = true;
  elements.sessionSummary.textContent = 'Не подключено';
  elements.messageText.disabled = true;
  elements.sendButton.disabled = true;
  setStatus(reason);
}

function mergeBuddyGroups(groups) {
  for (const group of groups || []) {
    const groupName = group.name || 'Buddies';
    for (const buddy of group.buddies || group.Buddies || []) {
      const contact = contactFromBuddy({ ...buddy, group: groupName });
      if (contact) {
        upsertContact({ ...contact, group: groupName });
      }
    }
  }
}

function renderContacts() {
  const filter = contactKey(elements.contactFilter.value);
  const contacts = Array.from(state.contacts.values())
    .filter((contact) => !filter || contactKey(contact.displayId || contact.aimId).includes(filter))
    .sort((a, b) => {
      const statusOrder = { online: 0, away: 1, idle: 2, dnd: 3, offline: 4 };
      const aStatus = statusOrder[contactStatus(a)] ?? 5;
      const bStatus = statusOrder[contactStatus(b)] ?? 5;
      if (aStatus !== bStatus) {
        return aStatus - bStatus;
      }
      return (a.displayId || a.aimId).localeCompare(b.displayId || b.aimId, 'ru');
    });

  elements.contactList.textContent = '';
  if (contacts.length === 0) {
    const empty = document.createElement('li');
    empty.className = 'empty-state';
    empty.textContent = filter ? 'Ничего не найдено' : 'Контактов пока нет';
    elements.contactList.append(empty);
    return;
  }

  for (const contact of contacts) {
    const status = contactStatus(contact);
    const item = document.createElement('li');
    const button = document.createElement('button');
    button.type = 'button';
    button.className = `contact ${status}${contactKey(state.selectedContact) === contactKey(contact.aimId) ? ' selected' : ''}`;
    button.addEventListener('click', () => selectContact(contact.aimId));

    const avatar = document.createElement('span');
    avatar.className = 'avatar';
    avatar.textContent = (contact.displayId || contact.aimId).slice(0, 2).toUpperCase();

    const main = document.createElement('span');
    main.className = 'contact-main';
    const name = document.createElement('span');
    name.className = 'contact-name';
    name.textContent = contact.displayId || contact.aimId;
    const meta = document.createElement('span');
    meta.className = 'contact-meta';
    meta.textContent = statusLabel(status);
    main.append(name, meta);

    const unread = unreadCount(contact.aimId);
    if (unread > 0) {
      const badge = document.createElement('span');
      badge.className = 'unread';
      badge.textContent = unread > 9 ? '9+' : String(unread);
      button.append(avatar, main, badge);
    } else {
      button.append(avatar, main);
    }

    item.append(button);
    elements.contactList.append(item);
  }
}

function unreadCount(contact) {
  const messages = state.history[contactKey(contact)] || [];
  return messages.filter((message) => message.unread).length;
}

function selectContact(aimId) {
  state.selectedContact = aimId;
  const messages = state.history[contactKey(aimId)] || [];
  for (const message of messages) {
    message.unread = false;
  }
  saveHistory();
  renderContacts();
  renderConversation();
}

function renderConversation() {
  const selected = state.selectedContact;
  const contact = selected ? state.contacts.get(contactKey(selected)) : null;
  elements.chatTitle.textContent = contact?.displayId || selected || 'Выберите контакт';
  elements.chatSubtitle.textContent = selected ? statusLabel(contactStatus(contact)) : 'История сообщений появится здесь.';
  elements.clearHistory.disabled = !selected;
  elements.messageText.disabled = !selected || !state.aimsid;
  elements.sendButton.disabled = !selected || !state.aimsid;
  elements.messages.textContent = '';

  if (!selected) {
    const empty = document.createElement('li');
    empty.className = 'conversation-empty';
    empty.textContent = 'Выберите контакт слева, чтобы начать переписку.';
    elements.messages.append(empty);
    return;
  }

  const messages = state.history[contactKey(selected)] || [];
  if (messages.length === 0) {
    const empty = document.createElement('li');
    empty.className = 'conversation-empty';
    empty.textContent = 'Сообщений пока нет.';
    elements.messages.append(empty);
    return;
  }

  for (const message of messages) {
    const item = document.createElement('li');
    item.className = `message ${message.direction}`;

    const bubble = document.createElement('div');
    bubble.className = 'bubble';
    const text = document.createElement('p');
    text.textContent = repairMojibake(message.text);
    const time = document.createElement('time');
    time.dateTime = new Date(message.timestamp).toISOString();
    time.textContent = new Date(message.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    bubble.append(text, time);
    item.append(bubble);
    elements.messages.append(item);
  }
  elements.messages.scrollTop = elements.messages.scrollHeight;
}

function storeMessage(contact, direction, text, timestamp = Date.now(), unread = false) {
  const key = contactKey(contact);
  const repairedText = repairMojibake(text);
  state.history[key] ||= [];
  const last = state.history[key].at(-1);
  if (last && last.direction === direction && last.text === repairedText && Math.abs(last.timestamp - timestamp) < 3000) {
    last.unread = last.unread || unread;
    saveHistory();
    return;
  }
  state.history[key].push({ direction, text: repairedText, timestamp, unread });
  state.history[key] = state.history[key].slice(-250);
  saveHistory();
}

async function login(event) {
  event.preventDefault();
  elements.loginButton.disabled = true;
  try {
    if (!state.apiKey) {
      await loadClientConfig();
    }

    state.screenName = normalizeName(elements.screenName.value);
    localStorage.setItem(`${STORAGE_PREFIX}.screenName`, state.screenName);

    setStatus('Входим…');
    const loginPayload = await postJSON('/auth/clientLogin', {
      username: state.screenName,
      password: elements.password.value,
    });
    state.token = responseData(loginPayload).token?.a;
    if (!state.token) {
      throw new Error('Сервер не вернул токен входа.');
    }

    setStatus('Подключаемся…');
    const sessionPayload = await getJSON('/aim/startSession', {
      k: state.apiKey,
      a: state.token,
      events: 'myInfo,buddylist,presence,im,sentIM,typing,offlineIM,sessionEnded',
      clientName: 'Open OSCAR ICQ Web',
      clientVersion: '3',
      sessionTimeout: '1800',
    });

    state.contacts.clear();
    state.selectedContact = '';
    setSignedIn(responseData(sessionPayload));
    try {
      await refreshContacts(false);
    } catch {
      // Initial buddy-list refresh is best effort; event polling will keep the UI current.
    }
    state.polling = true;
    pollEvents();
    showToast('Вы вошли.');
  } catch (error) {
    setSignedOut('Ошибка входа');
    showToast(error.message, true);
  } finally {
    elements.loginButton.disabled = false;
  }
}

async function refreshContacts(showNotice = false) {
  if (!state.aimsid) {
    return;
  }
  const payload = await getJSON('/presence/get', {
    aimsid: state.aimsid,
    bl: '1',
  });
  const data = responseData(payload);
  mergeBuddyGroups(data.groups || data.events?.buddylist?.groups || []);
  renderContacts();
  if (showNotice) {
    showToast('Контакты обновлены.');
  }
}

async function pollEvents() {
  while (state.polling && state.aimsid) {
    state.pollController = new AbortController();
    try {
      const response = await fetch(apiURL('/aim/fetchEvents', {
        f: 'json',
        aimsid: state.aimsid,
        seqNum: state.lastSeqNum,
        timeout: '25',
      }), { signal: state.pollController.signal });
      const payload = await readAPIResponse(response);
      const data = responseData(payload);
      state.lastSeqNum = data.lastSeqNum ?? state.lastSeqNum;
      for (const event of data.events || []) {
        handleServerEvent(event);
      }
    } catch (error) {
      if (!state.polling || error.name === 'AbortError') {
        return;
      }
      showToast(`Связь прервана: ${error.message}`, true);
      await new Promise((resolve) => setTimeout(resolve, 2500));
    }
  }
}

function stopPolling() {
  state.polling = false;
  state.pollController?.abort();
  state.pollController = null;
}

function handleServerEvent(event) {
  if (event.seqNum) {
    state.lastSeqNum = Math.max(state.lastSeqNum, event.seqNum);
  }

  if (event.type === 'presence') {
    const contact = contactFromBuddy(event.data || {});
    if (contact) {
      upsertContact(contact);
      renderContacts();
      if (state.selectedContact && contactKey(state.selectedContact) === contactKey(contact.aimId)) {
        renderConversation();
      }
    }
  }

  if (event.type === 'buddylist') {
    const data = event.data || {};
    const buddy = contactFromBuddy({ ...(data.buddy || {}), group: data.group });
    if (buddy) {
      upsertContact(buddy);
      renderContacts();
    }
  }

  if (event.type === 'im' || event.type === 'offlineIM') {
    const data = event.data || {};
    const from = data.from || data.sender?.aimId || 'unknown';
    upsertContact({ aimId: from, displayId: from, state: 'online' });
    const isSelected = state.selectedContact && contactKey(state.selectedContact) === contactKey(from);
    storeMessage(from, 'in', data.message || '', event.timestamp ? event.timestamp * 1000 : Date.now(), !isSelected);
    if (!state.selectedContact) {
      selectContact(from);
    } else {
      renderContacts();
      if (isSelected) {
        renderConversation();
      }
    }
  }

  if (event.type === 'sentIM') {
    const data = event.data || {};
    const peer = data.dest?.aimId || state.selectedContact || 'unknown';
    upsertContact({ aimId: peer, displayId: peer });
    storeMessage(peer, 'out', data.message || '', event.timestamp ? event.timestamp * 1000 : Date.now());
    renderContacts();
    if (state.selectedContact && contactKey(state.selectedContact) === contactKey(peer)) {
      renderConversation();
    }
  }

  if (event.type === 'sessionEnded') {
    setSignedOut('Сессия завершена');
  }
}

async function updateOwnPresence() {
  if (!state.aimsid) {
    return;
  }
  const wanted = elements.presenceState.value;
  const apiState = wanted === 'offline' ? 'invisible' : 'online';
  try {
    await getJSON('/presence/setState', {
      aimsid: state.aimsid,
      state: apiState,
    });
    state.presenceState = wanted;
    elements.sessionSummary.textContent = `${state.screenName} · ${wanted === 'offline' ? 'невидимый' : 'в сети'}`;
  } catch (error) {
    elements.presenceState.value = state.presenceState;
    showToast(`Не удалось изменить статус: ${error.message}`, true);
  }
}

async function addContact(event) {
  event.preventDefault();
  const buddy = normalizeName(elements.contactName.value);
  if (!buddy || !state.aimsid) {
    return;
  }
  try {
    const payload = await getJSON('/buddylist/addBuddy', {
      k: state.apiKey,
      aimsid: state.aimsid,
      buddy,
      group: 'Buddies',
    });
    const data = responseData(payload);
    upsertContact(contactFromBuddy(data.buddyInfo || { aimId: buddy, state: 'offline', group: 'Buddies' }));
    elements.contactName.value = '';
    renderContacts();
    selectContact(buddy);
    showToast(data.resultCode === 'alreadyExists' ? 'Контакт уже есть.' : 'Контакт добавлен.');
    await refreshContacts(false);
  } catch (error) {
    showToast(`Контакт не добавлен: ${error.message}`, true);
  }
}

async function sendMessage(event) {
  event.preventDefault();
  const recipient = state.selectedContact;
  const message = elements.messageText.value.trim();
  if (!recipient || !message || !state.aimsid) {
    return;
  }

  elements.sendButton.disabled = true;
  try {
    await getJSON('/im/sendIM', {
      aimsid: state.aimsid,
      t: recipient,
      message,
      offlineIM: '1',
    });
    storeMessage(recipient, 'out', message);
    renderContacts();
    renderConversation();
    elements.messageText.value = '';
  } catch (error) {
    showToast(`Сообщение не отправлено: ${error.message}`, true);
  } finally {
    elements.sendButton.disabled = !state.selectedContact || !state.aimsid;
  }
}

function clearCurrentHistory() {
  if (!state.selectedContact) {
    return;
  }
  delete state.history[contactKey(state.selectedContact)];
  saveHistory();
  renderContacts();
  renderConversation();
  showToast('История очищена.');
}

async function logout() {
  const aimsid = state.aimsid;
  setSignedOut();
  if (!aimsid) {
    return;
  }
  try {
    await getJSON('/aim/endSession', { aimsid });
    showToast('Вы вышли.');
  } catch {
    // Ignore logout races: the local session has already been cleared.
  }
}

function repairMojibake(text) {
  if (typeof text !== 'string' || !/[ÐÑРС]/.test(text)) {
    return text;
  }

  const bytes = [];
  for (const char of text) {
    const byte = windows1251Byte(char);
    if (byte === null) {
      return text;
    }
    bytes.push(byte);
  }

  try {
    const decoded = new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes));
    const originalCyrillic = (text.match(/[А-Яа-яЁё]/g) || []).length;
    const decodedCyrillic = (decoded.match(/[А-Яа-яЁё]/g) || []).length;
    return decodedCyrillic > originalCyrillic ? decoded : text;
  } catch {
    return text;
  }
}

function windows1251Byte(char) {
  const code = char.codePointAt(0);
  if (code <= 0x7f) {
    return code;
  }
  if (code >= 0x0410 && code <= 0x044f) {
    return code - 0x0410 + 0xc0;
  }

  const special = new Map([
    ['Ђ', 0x80], ['Ѓ', 0x81], ['‚', 0x82], ['ѓ', 0x83], ['„', 0x84], ['…', 0x85], ['†', 0x86], ['‡', 0x87],
    ['€', 0x88], ['‰', 0x89], ['Љ', 0x8a], ['‹', 0x8b], ['Њ', 0x8c], ['Ќ', 0x8d], ['Ћ', 0x8e], ['Џ', 0x8f],
    ['ђ', 0x90], ['‘', 0x91], ['’', 0x92], ['“', 0x93], ['”', 0x94], ['•', 0x95], ['–', 0x96], ['—', 0x97],
    ['™', 0x99], ['љ', 0x9a], ['›', 0x9b], ['њ', 0x9c], ['ќ', 0x9d], ['ћ', 0x9e], ['џ', 0x9f], [' ', 0xa0],
    ['Ў', 0xa1], ['ў', 0xa2], ['Ј', 0xa3], ['¤', 0xa4], ['Ґ', 0xa5], ['¦', 0xa6], ['§', 0xa7], ['Ё', 0xa8],
    ['©', 0xa9], ['Є', 0xaa], ['«', 0xab], ['¬', 0xac], ['­', 0xad], ['®', 0xae], ['Ї', 0xaf], ['°', 0xb0],
    ['±', 0xb1], ['І', 0xb2], ['і', 0xb3], ['ґ', 0xb4], ['µ', 0xb5], ['¶', 0xb6], ['·', 0xb7], ['ё', 0xb8],
    ['№', 0xb9], ['є', 0xba], ['»', 0xbb], ['ј', 0xbc], ['Ѕ', 0xbd], ['ѕ', 0xbe], ['ї', 0xbf],
  ]);
  return special.get(char) ?? null;
}
