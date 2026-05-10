const STORAGE_PREFIX = 'openOscar.webClient';
const MAX_EVENTS = 80;

const state = {
  apiKey: localStorage.getItem(`${STORAGE_PREFIX}.apiKey`) || '',
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
  sessionScreenName: $('session-screen-name'),
  sessionId: $('session-id'),
  lastSequence: $('last-sequence'),
  selectedContact: $('selected-contact'),
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
  eventLog: $('event-log'),
  clearEvents: $('clear-events'),
  toast: $('toast'),
};

elements.apiKey.value = state.apiKey;
elements.screenName.value = state.screenName;

elements.loginForm.addEventListener('submit', login);
elements.logoutButton.addEventListener('click', logout);
elements.presenceState.addEventListener('change', updateOwnPresence);
elements.refreshContacts.addEventListener('click', () => refreshContacts(true).catch((error) => {
  showToast(`Could not refresh contacts: ${error.message}`, true);
  logEvent('refresh contacts error', error.message, true);
}));
elements.addContactForm.addEventListener('submit', addContact);
elements.contactFilter.addEventListener('input', renderContacts);
elements.messageForm.addEventListener('submit', sendMessage);
elements.clearHistory.addEventListener('click', clearCurrentHistory);
elements.clearEvents.addEventListener('click', () => {
  elements.eventLog.textContent = '';
});
window.addEventListener('beforeunload', () => stopPolling());

renderContacts();
renderConversation();

function setStatus(text, mode = 'offline') {
  elements.status.textContent = text;
  elements.status.className = `status-pill ${mode}`;
}

function showToast(message, isError = false) {
  elements.toast.textContent = message;
  elements.toast.classList.toggle('error', isError);
  elements.toast.hidden = false;
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => {
    elements.toast.hidden = true;
  }, 4500);
}

function normalizeName(name) {
  return name.trim();
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
  if (!state.screenName) {
    return;
  }
  localStorage.setItem(historyKey(), JSON.stringify(state.history));
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
      throw new Error(`Unexpected response: ${text.slice(0, 180)}`);
    }
  }

  if (!response.ok) {
    throw new Error(payload?.response?.statusText || payload?.error || response.statusText);
  }

  const statusCode = payload?.response?.statusCode;
  if (statusCode && statusCode >= 400) {
    throw new Error(payload.response.statusText || `API error ${statusCode}`);
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

function logEvent(type, data, isError = false) {
  const item = document.createElement('li');
  item.className = `event${isError ? ' error' : ''}`;
  item.innerHTML = '<strong></strong><time></time><pre></pre>';
  item.querySelector('strong').textContent = type;
  item.querySelector('time').textContent = new Date().toLocaleTimeString();
  item.querySelector('pre').textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
  elements.eventLog.prepend(item);
  while (elements.eventLog.children.length > MAX_EVENTS) {
    elements.eventLog.lastElementChild.remove();
  }
}

function contactFromBuddy(buddy) {
  const aimId = normalizeName(buddy.aimId || buddy.screenName || buddy.displayId || buddy.name || String(buddy));
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
  return contact?.state === 'online' || contact?.state === 'away' || contact?.state === 'idle' || contact?.state === 'dnd'
    ? contact.state
    : 'offline';
}

function setSignedIn(data) {
  state.aimsid = data.aimsid;
  state.lastSeqNum = 0;
  state.presenceState = 'online';
  elements.presenceState.value = 'online';
  elements.loginPanel.hidden = true;
  elements.clientPanel.hidden = false;
  elements.logoutButton.hidden = false;
  elements.sessionSummary.textContent = `${state.screenName} · online`;
  elements.sessionScreenName.textContent = state.screenName;
  elements.sessionId.textContent = state.aimsid;
  elements.lastSequence.textContent = '0';
  setStatus(`Online as ${state.screenName}`, 'online');
  loadHistory();
  mergeBuddyGroups(data.events?.buddylist?.groups || []);
  renderContacts();
  renderConversation();
  logEvent('startSession', data);
}

function setSignedOut(reason = 'Signed out') {
  stopPolling();
  state.token = '';
  state.aimsid = '';
  state.lastSeqNum = 0;
  state.presenceState = 'offline';
  elements.loginPanel.hidden = false;
  elements.clientPanel.hidden = true;
  elements.logoutButton.hidden = true;
  elements.sessionSummary.textContent = 'Not connected';
  elements.sessionId.textContent = '—';
  elements.lastSequence.textContent = '0';
  elements.messageText.disabled = true;
  elements.sendButton.disabled = true;
  setStatus(reason, reason === 'Signed out' ? 'offline' : 'error');
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
  const filter = contactKey(elements.contactFilter.value || '');
  const contacts = [...state.contacts.values()]
    .filter((contact) => !filter || contactKey(contact.aimId).includes(filter) || contactKey(contact.displayId || '').includes(filter))
    .sort((a, b) => {
      const statusOrder = { online: 0, away: 1, idle: 2, dnd: 3, offline: 4 };
      const byStatus = (statusOrder[contactStatus(a)] ?? 9) - (statusOrder[contactStatus(b)] ?? 9);
      if (byStatus !== 0) {
        return byStatus;
      }
      return a.aimId.localeCompare(b.aimId);
    });

  elements.contactList.textContent = '';
  if (contacts.length === 0) {
    const empty = document.createElement('li');
    empty.className = 'empty-state';
    empty.textContent = state.aimsid ? 'No contacts yet. Add a buddy above.' : 'Sign in to load contacts.';
    elements.contactList.append(empty);
    return;
  }

  for (const contact of contacts) {
    const item = document.createElement('li');
    const button = document.createElement('button');
    const status = contactStatus(contact);
    button.type = 'button';
    button.className = `contact ${state.selectedContact && contactKey(state.selectedContact) === contactKey(contact.aimId) ? 'selected' : ''}`;
    button.innerHTML = `
      <span class="avatar" aria-hidden="true">${escapeInitials(contact.displayId || contact.aimId)}</span>
      <span class="contact-main">
        <span class="contact-name"></span>
        <span class="contact-meta"><span class="dot ${status}"></span>${statusLabel(status)}</span>
      </span>
      <span class="unread" hidden></span>
    `;
    button.querySelector('.contact-name').textContent = contact.displayId || contact.aimId;
    const history = state.history[contactKey(contact.aimId)] || [];
    const unread = history.filter((message) => message.unread).length;
    const unreadEl = button.querySelector('.unread');
    if (unread > 0) {
      unreadEl.textContent = unread > 99 ? '99+' : String(unread);
      unreadEl.hidden = false;
    }
    button.addEventListener('click', () => selectContact(contact.aimId));
    item.append(button);
    elements.contactList.append(item);
  }
}

function statusLabel(status) {
  switch (status) {
    case 'online': return 'online';
    case 'away': return 'away';
    case 'idle': return 'idle';
    case 'dnd': return 'do not disturb';
    default: return 'offline';
  }
}

function escapeInitials(name) {
  const text = normalizeName(name).replace(/[^a-zA-Z0-9]/g, '');
  return (text.slice(0, 2) || '?').toUpperCase();
}

function selectContact(aimId) {
  state.selectedContact = aimId;
  const key = contactKey(aimId);
  for (const message of state.history[key] || []) {
    message.unread = false;
  }
  saveHistory();
  renderContacts();
  renderConversation();
  elements.messageText.focus();
}

function renderConversation() {
  const selected = state.selectedContact;
  elements.messages.textContent = '';
  elements.selectedContact.textContent = selected || '—';
  elements.clearHistory.disabled = !selected;
  elements.messageText.disabled = !selected || !state.aimsid;
  elements.sendButton.disabled = !selected || !state.aimsid;

  if (!selected) {
    elements.chatTitle.textContent = 'Choose a contact';
    elements.chatSubtitle.textContent = 'Select someone from the contact list to start chatting.';
    const empty = document.createElement('li');
    empty.className = 'empty-conversation';
    empty.textContent = 'No conversation selected.';
    elements.messages.append(empty);
    return;
  }

  const contact = state.contacts.get(contactKey(selected));
  const status = contactStatus(contact);
  elements.chatTitle.textContent = contact?.displayId || selected;
  elements.chatSubtitle.textContent = `${statusLabel(status)} · history is saved locally in this browser`;

  const history = state.history[contactKey(selected)] || [];
  if (history.length === 0) {
    const empty = document.createElement('li');
    empty.className = 'empty-conversation';
    empty.textContent = 'No messages yet.';
    elements.messages.append(empty);
    return;
  }

  for (const message of history) {
    appendMessageElement(message);
  }
  elements.messages.scrollTop = elements.messages.scrollHeight;
}

function appendMessageElement(message) {
  const item = document.createElement('li');
  item.className = `message ${message.direction}`;
  const date = new Date(message.timestamp);
  item.innerHTML = '<div class="bubble"><div class="message-meta"></div><div class="message-body"></div></div>';
  item.querySelector('.message-meta').textContent = `${message.direction === 'out' ? 'You' : message.peer} · ${date.toLocaleString()}`;
  item.querySelector('.message-body').textContent = message.text;
  elements.messages.append(item);
}

function storeMessage(peer, direction, text, timestamp = Date.now(), unread = false) {
  const key = contactKey(peer);
  state.history[key] ||= [];
  state.history[key].push({ peer, direction, text, timestamp, unread });
  if (state.history[key].length > 500) {
    state.history[key] = state.history[key].slice(-500);
  }
  saveHistory();
}

async function login(event) {
  event.preventDefault();
  elements.loginButton.disabled = true;
  try {
    state.apiKey = elements.apiKey.value.trim();
    state.screenName = normalizeName(elements.screenName.value);
    localStorage.setItem(`${STORAGE_PREFIX}.apiKey`, state.apiKey);
    localStorage.setItem(`${STORAGE_PREFIX}.screenName`, state.screenName);

    setStatus('Authenticating…', 'offline');
    const loginPayload = await postJSON('/auth/clientLogin', {
      username: state.screenName,
      password: elements.password.value,
    });
    state.token = responseData(loginPayload).token?.a;
    if (!state.token) {
      throw new Error('Login response did not include an auth token.');
    }

    setStatus('Starting session…', 'offline');
    const sessionPayload = await getJSON('/aim/startSession', {
      k: state.apiKey,
      a: state.token,
      events: 'myInfo,buddylist,presence,im,sentIM,typing,offlineIM,sessionEnded',
      clientName: 'Open OSCAR Web Client',
      clientVersion: '2',
      sessionTimeout: '1800',
    });

    state.contacts.clear();
    state.selectedContact = '';
    setSignedIn(responseData(sessionPayload));
    try {
      await refreshContacts(false);
    } catch (error) {
      logEvent('refresh contacts warning', error.message, true);
    }
    state.polling = true;
    pollEvents();
    showToast('Signed in successfully.');
  } catch (error) {
    setSignedOut('Sign-in failed');
    showToast(error.message, true);
    logEvent('login error', error.message, true);
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
  mergeBuddyGroups(responseData(payload).groups || []);
  renderContacts();
  if (showNotice) {
    showToast('Contacts refreshed.');
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
      elements.lastSequence.textContent = String(state.lastSeqNum);
      for (const event of data.events || []) {
        handleServerEvent(event);
      }
    } catch (error) {
      if (!state.polling || error.name === 'AbortError') {
        return;
      }
      logEvent('poll error', error.message, true);
      showToast(`Event polling failed: ${error.message}`, true);
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
  logEvent(event.type || 'event', event);
  if (event.seqNum) {
    state.lastSeqNum = Math.max(state.lastSeqNum, event.seqNum);
    elements.lastSequence.textContent = String(state.lastSeqNum);
  }

  if (event.type === 'presence') {
    const data = event.data || {};
    const contact = contactFromBuddy(data);
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
    setSignedOut('Session ended');
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
    elements.sessionSummary.textContent = `${state.screenName} · ${wanted}`;
    setStatus(`${wanted === 'offline' ? 'Invisible' : 'Online'} as ${state.screenName}`, wanted === 'offline' ? 'offline' : 'online');
    logEvent('presence/setState', { state: wanted, apiState });
  } catch (error) {
    elements.presenceState.value = state.presenceState;
    showToast(`Could not change status: ${error.message}`, true);
    logEvent('presence error', error.message, true);
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
    showToast(data.resultCode === 'alreadyExists' ? 'Contact already exists.' : 'Contact added.');
    await refreshContacts(false);
  } catch (error) {
    showToast(`Contact was not added: ${error.message}`, true);
    logEvent('add contact error', error.message, true);
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
    const payload = await getJSON('/im/sendIM', {
      aimsid: state.aimsid,
      t: recipient,
      message,
      offlineIM: '1',
    });
    elements.messageText.value = '';
    logEvent('sendIM', responseData(payload));
  } catch (error) {
    showToast(`Message not sent: ${error.message}`, true);
    logEvent('sendIM error', error.message, true);
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
  showToast('Conversation history cleared.');
}

async function logout() {
  const aimsid = state.aimsid;
  setSignedOut();
  if (!aimsid) {
    return;
  }
  try {
    await getJSON('/aim/endSession', { aimsid });
    showToast('Signed out.');
  } catch (error) {
    logEvent('endSession warning', error.message, true);
  }
}
