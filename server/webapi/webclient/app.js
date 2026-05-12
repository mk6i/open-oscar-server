const STORAGE_PREFIX = 'openOscar.webClient';
const ICQ_EMOTICONS = [':-)', ';-)', ':-D', ':-P', ':-(', ':-O', ':-*', ':-[', ':-X', '8-)', ':-/', ':-!'];
const CONTACT_REFRESH_INTERVAL_MS = 15000;

const state = {
  apiKey: '',
  screenName: localStorage.getItem(`${STORAGE_PREFIX}.screenName`) || '',
  token: '',
  aimsid: '',
  lastSeqNum: 0,
  polling: false,
  pollController: null,
  contactRefreshTimer: null,
  refreshingContacts: false,
  audioContext: null,
  contacts: new Map(),
  selectedContact: '',
  presenceState: 'online',
  history: {},
  aliases: JSON.parse(localStorage.getItem(`${STORAGE_PREFIX}.aliases`) || '{}'),
  avatars: JSON.parse(localStorage.getItem(`${STORAGE_PREFIX}.avatars`) || '{}'),
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
  emojiButton: $('emoji-button'),
  emojiPicker: $('emoji-picker'),
  sendButton: $('send-button'),
  avatarButton: $('avatar-button'),
  avatarInput: $('avatar-input'),
  selfName: $('self-name'),
  contactActionsName: $('contact-actions-name'),
  renameContact: $('rename-contact'),
  deleteContact: $('delete-contact'),
  blockContact: $('block-contact'),
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
elements.messageText.addEventListener('keydown', handleComposerKeydown);
elements.emojiButton.addEventListener('click', toggleEmojiPicker);
elements.avatarButton.addEventListener('click', () => elements.avatarInput.click());
elements.avatarInput.addEventListener('change', updateAvatar);
elements.renameContact.addEventListener('click', renameSelectedContact);
elements.deleteContact.addEventListener('click', deleteSelectedContact);
elements.blockContact.addEventListener('click', blockSelectedContact);
elements.clearHistory.addEventListener('click', clearCurrentHistory);
window.addEventListener('beforeunload', () => stopPolling());
window.addEventListener('visibilitychange', () => {
  if (!document.hidden) {
    refreshContacts(false).catch(() => {});
  }
});

loadClientConfig().catch((error) => {
  setStatus('Клиент не настроен');
  showToast(error.message, true);
});
renderEmojiPicker();
applyOwnAvatar();
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

function displayNameFor(aimId, fallback = aimId) {
  return state.aliases[contactKey(aimId)] || fallback || aimId;
}

function saveAliases() {
  localStorage.setItem(`${STORAGE_PREFIX}.aliases`, JSON.stringify(state.aliases));
}

function saveAvatars() {
  localStorage.setItem(`${STORAGE_PREFIX}.avatars`, JSON.stringify(state.avatars));
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
    displayId: displayNameFor(aimId, buddy.displayId || aimId),
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
  return ['online', 'away', 'na', 'occupied', 'dnd', 'freechat', 'idle', 'invisible'].includes(contact?.state) ? contact.state : 'offline';
}

function statusLabel(status) {
  const labels = {
    online: 'в сети',
    away: 'отошёл',
    na: 'недоступен',
    occupied: 'занят',
    dnd: 'не беспокоить',
    freechat: 'свободен для разговора',
    idle: 'неактивен',
    invisible: 'невидимый',
    offline: 'не в сети',
  };
  return labels[status] || 'не в сети';
}

function setSignedIn(data) {
  state.aimsid = data.aimsid;
  state.lastSeqNum = 0;
  state.presenceState = 'online';
  elements.presenceState.value = 'online';
  elements.loginPanel.hidden = true;
  elements.clientPanel.hidden = false;
  elements.sessionSummary.textContent = `${state.screenName} · в сети`;
  elements.selfName.textContent = state.screenName;
  setStatus(`В сети: ${state.screenName}`);
  loadHistory();
  mergeBuddyGroups(data.events?.buddylist?.groups || data.myInfo?.buddylist?.groups || []);
  renderContacts();
  renderConversation();
  startAutomaticContactRefresh();
}

function setSignedOut(reason = 'Ожидание входа') {
  stopPolling();
  stopAutomaticContactRefresh();
  state.token = '';
  state.aimsid = '';
  state.lastSeqNum = 0;
  state.presenceState = 'online';
  elements.loginPanel.hidden = false;
  elements.clientPanel.hidden = true;
  elements.sessionSummary.textContent = 'Не подключено';
  elements.messageText.disabled = true;
  elements.emojiButton.disabled = true;
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
      const statusOrder = { online: 0, freechat: 1, away: 2, na: 3, occupied: 4, dnd: 5, idle: 6, offline: 7 };
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
    const avatarData = state.avatars[contactKey(contact.aimId)];
    if (avatarData) {
      avatar.style.backgroundImage = `url(${avatarData})`;
      avatar.textContent = '';
    } else {
      avatar.textContent = (contact.displayId || contact.aimId).slice(0, 2).toUpperCase();
    }

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
  elements.chatTitle.textContent = selected ? displayNameFor(selected, contact?.displayId || selected) : 'Выберите контакт';
  elements.chatSubtitle.textContent = selected ? statusLabel(contactStatus(contact)) : 'История сообщений появится здесь.';
  elements.clearHistory.disabled = !selected;
  elements.messageText.disabled = !selected || !state.aimsid;
  elements.emojiButton.disabled = !selected || !state.aimsid;
  elements.sendButton.disabled = !selected || !state.aimsid;
  elements.renameContact.disabled = !selected;
  elements.deleteContact.disabled = !selected;
  elements.blockContact.disabled = !selected;
  elements.contactActionsName.textContent = selected ? displayNameFor(selected) : 'Выберите контакт';
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
      events: 'myInfo,buddylist,presence,im,sentIM,typing,offlineIM,authorization,sessionEnded',
      clientName: 'Open OSCAR ICQ Web',
      clientVersion: '3',
      sessionTimeout: '1800',
    });

    unlockIncomingSound();
    state.contacts.clear();
    state.selectedContact = '';
    setSignedIn(responseData(sessionPayload));
    try {
      await refreshContacts(false);
    } catch {
      // Initial buddy-list refresh is best effort; automatic refresh and event polling will keep the UI current.
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
  if (!state.aimsid || state.refreshingContacts) {
    return;
  }
  state.refreshingContacts = true;
  try {
    const payload = await getJSON('/presence/get', {
      aimsid: state.aimsid,
      bl: '1',
    });
    const data = responseData(payload);
    mergeBuddyGroups(data.groups || data.events?.buddylist?.groups || []);
    renderContacts();
    if (state.selectedContact) {
      renderConversation();
    }
    if (showNotice) {
      showToast('Контакты обновлены.');
    }
  } finally {
    state.refreshingContacts = false;
  }
}

function startAutomaticContactRefresh() {
  stopAutomaticContactRefresh();
  state.contactRefreshTimer = window.setInterval(() => {
    refreshContacts(false).catch(() => {});
  }, CONTACT_REFRESH_INTERVAL_MS);
}

function stopAutomaticContactRefresh() {
  if (state.contactRefreshTimer) {
    window.clearInterval(state.contactRefreshTimer);
    state.contactRefreshTimer = null;
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
      if ((data.events || []).some((event) => ['buddylist', 'presence'].includes(event.type))) {
        refreshContacts(false).catch(() => {});
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
    playIncomingSound();
    if (!state.selectedContact) {
      selectContact(from);
    } else {
      renderContacts();
      if (isSelected) {
        renderConversation();
      }
    }
  }

  if (event.type === 'authorization') {
    handleAuthorizationEvent(event.data || {});
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

function unlockIncomingSound() {
  const AudioContext = window.AudioContext || window.webkitAudioContext;
  if (!AudioContext || state.audioContext) {
    return;
  }
  try {
    state.audioContext = new AudioContext();
    state.audioContext.resume?.();
  } catch {
    state.audioContext = null;
  }
}

function playIncomingSound() {
  const AudioContext = window.AudioContext || window.webkitAudioContext;
  if (!AudioContext) {
    return;
  }
  try {
    const ctx = state.audioContext || new AudioContext();
    state.audioContext = ctx;
    ctx.resume?.();
    const now = ctx.currentTime;
    const gain = ctx.createGain();
    gain.gain.setValueAtTime(0.0001, now);
    gain.gain.exponentialRampToValueAtTime(0.16, now + 0.01);
    gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.26);
    gain.connect(ctx.destination);

    for (const [offset, frequency] of [[0, 880], [0.12, 1174]]) {
      const oscillator = ctx.createOscillator();
      oscillator.type = 'sine';
      oscillator.frequency.setValueAtTime(frequency, now + offset);
      oscillator.connect(gain);
      oscillator.start(now + offset);
      oscillator.stop(now + offset + 0.12);
    }
  } catch {
    // Some browsers block audio until the next direct user gesture.
  }
}

async function handleAuthorizationEvent(data) {
  if (data.action !== 'request' || !state.aimsid) {
    return;
  }
  const requester = normalizeName(data.from || data.aimId || data.screenName);
  if (!requester) {
    return;
  }
  playIncomingSound();
  const reason = data.reason ? `\n\nСообщение: ${data.reason}` : '';
  const accepted = window.confirm(`${displayNameFor(requester)} просит авторизацию для добавления вас в контакт-лист.${reason}\n\nРазрешить?`);
  const responseReason = accepted ? 'Авторизация разрешена' : 'Авторизация отклонена';
  try {
    await getJSON('/buddylist/respondAuthorize', {
      aimsid: state.aimsid,
      buddy: requester,
      accepted: accepted ? '1' : '0',
      reason: responseReason,
    });
    if (accepted) {
      upsertContact({ aimId: requester, displayId: requester, state: 'offline', group: 'Buddies' });
      renderContacts();
      await refreshContacts(false);
    }
    showToast(accepted ? 'Авторизация контакта разрешена.' : 'Авторизация контакта отклонена.');
  } catch (error) {
    showToast(`Не удалось отправить ответ авторизации: ${error.message}`, true);
  }
}

async function updateOwnPresence() {
  if (!state.aimsid) {
    return;
  }
  const wanted = elements.presenceState.value;
  const stateMap = { offline: 'invisible', invisible: 'invisible', na: 'na', occupied: 'occupied', freechat: 'freechat' };
  const apiState = stateMap[wanted] || wanted;
  try {
    await getJSON('/presence/setState', {
      aimsid: state.aimsid,
      state: apiState,
    });
    state.presenceState = wanted;
    elements.sessionSummary.textContent = `${state.screenName} · ${statusLabel(wanted)}`;
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


function handleComposerKeydown(event) {
  if (event.key === 'Enter' && event.ctrlKey) {
    event.preventDefault();
    elements.messageForm.requestSubmit();
  }
}

function renderEmojiPicker() {
  elements.emojiPicker.textContent = '';
  for (const emoji of ICQ_EMOTICONS) {
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = emoji;
    button.addEventListener('click', () => insertAtCursor(`${emoji} `));
    elements.emojiPicker.append(button);
  }
}

function toggleEmojiPicker() {
  elements.emojiPicker.hidden = !elements.emojiPicker.hidden;
}

function insertAtCursor(text) {
  const input = elements.messageText;
  const start = input.selectionStart ?? input.value.length;
  const end = input.selectionEnd ?? input.value.length;
  input.value = `${input.value.slice(0, start)}${text}${input.value.slice(end)}`;
  input.focus();
  input.selectionStart = input.selectionEnd = start + text.length;
}

function applyOwnAvatar() {
  const avatarData = state.avatars[contactKey(state.screenName)];
  elements.avatarButton.style.backgroundImage = avatarData ? `url(${avatarData})` : '';
  elements.avatarButton.textContent = avatarData ? '' : '✿';
}

function updateAvatar(event) {
  const file = event.target.files?.[0];
  if (!file) {
    return;
  }
  if (!['image/jpeg', 'image/png'].includes(file.type)) {
    showToast('Можно выбрать только JPG или PNG.', true);
    return;
  }

  const img = new Image();
  img.onload = () => {
    const maxSize = 256;
    const scale = Math.min(1, maxSize / Math.max(img.width, img.height));
    const width = Math.max(1, Math.round(img.width * scale));
    const height = Math.max(1, Math.round(img.height * scale));
    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0, width, height);
    state.avatars[contactKey(state.screenName)] = canvas.toDataURL(file.type, 0.88);
    saveAvatars();
    applyOwnAvatar();
    showToast('Аватар обновлён в веб-клиенте.');
  };
  img.src = URL.createObjectURL(file);
}

async function renameSelectedContact() {
  if (!state.selectedContact) {
    return;
  }
  const current = displayNameFor(state.selectedContact);
  const next = window.prompt('Новое имя контакта', current);
  if (!next) {
    return;
  }
  state.aliases[contactKey(state.selectedContact)] = normalizeName(next);
  saveAliases();
  const contact = state.contacts.get(contactKey(state.selectedContact));
  if (contact) {
    contact.displayId = normalizeName(next);
  }
  renderContacts();
  renderConversation();
}

async function deleteSelectedContact() {
  const contact = state.selectedContact;
  if (!contact || !window.confirm(`Удалить ${displayNameFor(contact)} из списка контактов?`)) {
    return;
  }
  await getJSON('/buddylist/removeBuddy', { aimsid: state.aimsid, buddy: contact });
  state.contacts.delete(contactKey(contact));
  state.selectedContact = '';
  renderContacts();
  renderConversation();
}

async function blockSelectedContact() {
  const contact = state.selectedContact;
  if (!contact || !window.confirm(`Заблокировать ${displayNameFor(contact)}?`)) {
    return;
  }
  await getJSON('/buddylist/blockBuddy', { aimsid: state.aimsid, buddy: contact });
  showToast('Контакт заблокирован.');
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
