(function appBootstrap() {
  const state = {
    map: null,
    mapConfig: null,
    isAuthenticated: false,
    currentMapMode: 'standard',
    // tileLayers/activeTileLayer used in Leaflet implementation - removed
    // boundary/world mask layers are managed via MapLibre sources/layers
    cityBounds: null,
    cityMinZoom: null,
    markers: new Map(),
    activePopupPinId: null,
    mapPickMode: false,
    mapPickFile: null,
    mapPickMarker: null,
    mapPickBusy: false,
    replacePinId: null,
    moveState: null,
    toastTimer: null,
    dialogResolver: null,
    mapInitialized: false,
    maxImageSizeBytes: 12 * 1024 * 1024,
    fullscreenGuardUntil: 0,
    authInProgress: false,
  };

  const elements = {
    map: document.getElementById('map'),
    uploadButton: document.getElementById('uploadButton'),
    logoutButton: document.getElementById('logoutButton'),
    imageInput: document.getElementById('imageInput'),
    replaceImageInput: document.getElementById('replaceImageInput'),
    modeButtons: Array.from(document.querySelectorAll('.mode-btn')),
    statusLine: document.getElementById('statusLine'),
    authOverlay: document.getElementById('authOverlay'),
    loginForm: document.getElementById('loginForm'),
    loginSubmitButton: document.querySelector('#loginForm button[type="submit"]'),
    usernameInput: document.getElementById('usernameInput'),
    passwordInput: document.getElementById('passwordInput'),
    loginError: document.getElementById('loginError'),
    mapPickBanner: document.getElementById('mapPickBanner'),
    cancelMapPickButton: document.getElementById('cancelMapPickButton'),
    moveToolbar: document.getElementById('moveToolbar'),
    saveMoveButton: document.getElementById('saveMoveButton'),
    cancelMoveButton: document.getElementById('cancelMoveButton'),
    fullscreenOverlay: document.getElementById('fullscreenOverlay'),
    fullscreenImage: document.getElementById('fullscreenImage'),
    fullscreenCaption: document.getElementById('fullscreenCaption'),
    closeFullscreenButton: document.getElementById('closeFullscreenButton'),
    toast: document.getElementById('toast'),
    dialogOverlay: document.getElementById('dialogOverlay'),
    dialogTitle: document.getElementById('dialogTitle'),
    dialogMessage: document.getElementById('dialogMessage'),
    dialogInputWrap: document.getElementById('dialogInputWrap'),
    dialogInputLabel: document.getElementById('dialogInputLabel'),
    dialogInput: document.getElementById('dialogInput'),
    dialogButtons: document.getElementById('dialogButtons'),
  };

  document.addEventListener('DOMContentLoaded', () => {
    bindEvents();
    bootstrapSession();
  });

  function bindEvents() {
    elements.loginForm.addEventListener('submit', onLoginSubmit);
    elements.logoutButton.addEventListener('click', onLogoutClick);
    elements.uploadButton.addEventListener('click', () => {
      if (!ensureAuthenticatedForEdit('caricare immagini')) {
        return;
      }
      elements.imageInput.click();
    });

    elements.imageInput.addEventListener('change', async (event) => {
      const file = event.target.files && event.target.files[0];
      event.target.value = '';
      if (file) {
        await startUploadFlow(file);
      }
    });

    elements.replaceImageInput.addEventListener('change', async (event) => {
      const file = event.target.files && event.target.files[0];
      event.target.value = '';
      if (!file || !state.replacePinId) {
        return;
      }

      const pinId = state.replacePinId;
      state.replacePinId = null;
      await replacePinImage(pinId, file);
    });

    elements.modeButtons.forEach((button) => {
      button.addEventListener('click', () => {
        setMapMode(button.dataset.mode);
      });
    });

    elements.cancelMapPickButton.addEventListener('click', () => {
      stopMapPickMode();
      setStatus('Selezione da mappa annullata.');
    });

    elements.saveMoveButton.addEventListener('click', saveMovePinPosition);
    elements.cancelMoveButton.addEventListener('click', cancelMovePinPosition);

    elements.closeFullscreenButton.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopPropagation();
      closeFullscreen();
    });
    elements.fullscreenOverlay.addEventListener('click', (event) => {
      if (event.target === elements.fullscreenOverlay) {
        event.preventDefault();
        event.stopPropagation();
        closeFullscreen();
      }
    });

    elements.authOverlay.addEventListener('click', (event) => {
      if (event.target === elements.authOverlay) {
        closeAuthOverlay();
      }
    });

    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') {
        if (!elements.fullscreenOverlay.classList.contains('is-hidden')) {
          closeFullscreen();
        } else if (!elements.dialogOverlay.classList.contains('is-hidden')) {
          resolveDialog(null);
        } else if (!elements.authOverlay.classList.contains('is-hidden')) {
          closeAuthOverlay();
        }
      }
    });
  }

  async function bootstrapSession() {
    try {
      const session = await apiFetch('/api/auth/session', { skipAuthHandling: true });
      state.isAuthenticated = Boolean(session.authenticated);
      setAuthUiState();
      closeAuthOverlay();
      await initializeApp();
      if (!state.isAuthenticated) {
        setStatus('Modalita visualizzazione. Accedi per modificare pin.');
      }
    } catch (error) {
      setStatus(error.message || 'Errore durante il caricamento sessione', 'error');
    }
  }

  async function onLoginSubmit(event) {
    event.preventDefault();
    elements.loginError.textContent = '';

    if (state.authInProgress) {
      return;
    }

    const username = elements.usernameInput.value.trim();
    const password = elements.passwordInput.value;
    if (!username || !password) {
      elements.loginError.textContent = 'Inserisci username e password.';
      return;
    }

    setLoginBusy(true);

    try {
      const loginResult = await apiFetch('/api/auth/login', {
        method: 'POST',
        body: { username, password },
        skipAuthHandling: true,
      });

      const finalResult = await processAuthFlowStep(loginResult);
      await completeLoginSuccess(finalResult && finalResult.username ? finalResult.username : username);
    } catch (error) {
      elements.loginError.textContent = error.message || 'Login non riuscito';
    } finally {
      setLoginBusy(false);
    }
  }

  function setLoginBusy(busy) {
    state.authInProgress = Boolean(busy);
    if (elements.loginSubmitButton) {
      elements.loginSubmitButton.disabled = state.authInProgress;
      elements.loginSubmitButton.textContent = state.authInProgress ? 'Accesso in corso...' : 'Accedi';
    }
  }

  async function completeLoginSuccess(username) {
    state.isAuthenticated = true;
    setAuthUiState();
    closeAuthOverlay();
    elements.passwordInput.value = '';
    await initializeApp();
    setStatus(`Accesso effettuato${username ? ` (${username})` : ''}.`, 'success');
  }

  async function processAuthFlowStep(stepResult) {
    let current = stepResult;
    while (current && !current.ok) {
      if (current.step === 'passkey_setup') {
        current = await handlePasskeySetupStep(current);
        continue;
      }

      if (current.step === 'passkey') {
        current = await handlePasskeyAuthenticationStep(current);
        continue;
      }

      throw new Error('Passo autenticazione non supportato dal client');
    }

    if (!current || !current.ok) {
      throw new Error('Autenticazione non completata');
    }

    return current;
  }

  async function handlePasskeySetupStep(stepData) {
    ensurePasskeySupport();
    if (!stepData.token || !stepData.options) {
      throw new Error('Dati passkey non validi');
    }

    setStatus('Registrazione passkey in corso...');
    const publicKeyOptions = parseRegistrationOptions(stepData.options);
    const credential = await navigator.credentials.create({ publicKey: publicKeyOptions });
    if (!credential) {
      throw new Error('Registrazione passkey annullata');
    }

    const credentialJson = publicKeyCredentialToJson(credential);
    return apiFetch('/api/auth/passkey/register/verify', {
      method: 'POST',
      body: {
        token: stepData.token,
        credential: credentialJson,
      },
      skipAuthHandling: true,
    });
  }

  async function handlePasskeyAuthenticationStep(stepData) {
    ensurePasskeySupport();
    if (!stepData.token || !stepData.options) {
      throw new Error('Dati passkey non validi');
    }

    setStatus('Verifica passkey in corso...');
    const publicKeyOptions = parseAuthenticationOptions(stepData.options);
    const credential = await navigator.credentials.get({ publicKey: publicKeyOptions });
    if (!credential) {
      throw new Error('Verifica passkey annullata');
    }

    const credentialJson = publicKeyCredentialToJson(credential);
    return apiFetch('/api/auth/passkey/authenticate/verify', {
      method: 'POST',
      body: {
        token: stepData.token,
        credential: credentialJson,
      },
      skipAuthHandling: true,
    });
  }

  function ensurePasskeySupport() {
    if (!window.PublicKeyCredential || !navigator.credentials) {
      throw new Error('Questo browser non supporta passkey/WebAuthn');
    }
  }

  function parseRegistrationOptions(optionsJson) {
    if (window.PublicKeyCredential && typeof window.PublicKeyCredential.parseCreationOptionsFromJSON === 'function') {
      return window.PublicKeyCredential.parseCreationOptionsFromJSON(optionsJson);
    }

    const normalized = { ...optionsJson };
    normalized.challenge = base64UrlToArrayBuffer(optionsJson.challenge);
    normalized.user = {
      ...(optionsJson.user || {}),
      id: base64UrlToArrayBuffer(optionsJson.user.id),
    };
    normalized.excludeCredentials = Array.isArray(optionsJson.excludeCredentials)
      ? optionsJson.excludeCredentials.map((item) => ({
        ...item,
        id: base64UrlToArrayBuffer(item.id),
      }))
      : [];
    return normalized;
  }

  function parseAuthenticationOptions(optionsJson) {
    if (window.PublicKeyCredential && typeof window.PublicKeyCredential.parseRequestOptionsFromJSON === 'function') {
      return window.PublicKeyCredential.parseRequestOptionsFromJSON(optionsJson);
    }

    const normalized = { ...optionsJson };
    normalized.challenge = base64UrlToArrayBuffer(optionsJson.challenge);
    normalized.allowCredentials = Array.isArray(optionsJson.allowCredentials)
      ? optionsJson.allowCredentials.map((item) => ({
        ...item,
        id: base64UrlToArrayBuffer(item.id),
      }))
      : [];
    return normalized;
  }

  function publicKeyCredentialToJson(credential) {
    if (credential && typeof credential.toJSON === 'function') {
      return credential.toJSON();
    }

    const response = credential.response || {};
    const base = {
      id: credential.id,
      rawId: arrayBufferToBase64Url(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment || undefined,
      clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
    };

    if (response.attestationObject) {
      base.response = {
        clientDataJSON: arrayBufferToBase64Url(response.clientDataJSON),
        attestationObject: arrayBufferToBase64Url(response.attestationObject),
        transports: typeof response.getTransports === 'function' ? response.getTransports() : [],
      };
      return base;
    }

    base.response = {
      clientDataJSON: arrayBufferToBase64Url(response.clientDataJSON),
      authenticatorData: arrayBufferToBase64Url(response.authenticatorData),
      signature: arrayBufferToBase64Url(response.signature),
      userHandle: response.userHandle ? arrayBufferToBase64Url(response.userHandle) : undefined,
    };
    return base;
  }

  function base64UrlToArrayBuffer(value) {
    const normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
    const padding = '='.repeat((4 - (normalized.length % 4)) % 4);
    const binary = atob(normalized + padding);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes.buffer;
  }

  function arrayBufferToBase64Url(value) {
    const bytes = value instanceof Uint8Array ? value : new Uint8Array(value || []);
    let binary = '';
    bytes.forEach((byte) => {
      binary += String.fromCharCode(byte);
    });
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  async function onLogoutClick() {
    if (!state.isAuthenticated) {
      openAuthOverlay();
      return;
    }

    try {
      await apiFetch('/api/auth/logout', { method: 'POST' });
    } catch (_error) {
      // Ignora errori logout.
    }

    state.isAuthenticated = false;
    setAuthUiState();
    closeAuthOverlay();
    setStatus('Modalita visualizzazione attiva. Accedi per modificare pin.');
  }

  async function initializeApp() {
    if (!state.mapInitialized) {
      await loadMapConfigAndInit();
      state.mapInitialized = true;
    }

    await loadPins();
  }

  async function loadMapConfigAndInit() {
    const config = await apiFetch('/api/config');
    state.mapConfig = config;
    state.maxImageSizeBytes = (Number(config.maxImageSizeMb) || 12) * 1024 * 1024;

    // compute center and bounds in [lng,lat] order for MapLibre
    const center = [config.macerata.center[0], config.macerata.center[1]];
    const bounds = [
      [config.macerata.bounds[0][0], config.macerata.bounds[0][1]],
      [config.macerata.bounds[1][0], config.macerata.bounds[1][1]],
    ];
    state.cityBounds = bounds;

    // create MapLibre GL map
    state.map = new maplibregl.Map({
      container: elements.map,
      style: getMapLibreStyle(state.currentMapMode),
      center,
      zoom: 12.8,
      minZoom: 5,
      maxZoom: 19,
      maxBounds: bounds,
    });

    // navigation control includes rotation buttons
    state.map.addControl(new maplibregl.NavigationControl({ showCompass: true, showZoom: true }), 'bottomright');

    state.map.on('click', (e) => {
      if (state.mapPickMode) {
        // adapt to the original handler signature
        onMapPickClick({ latlng: { lat: e.lngLat.lat, lng: e.lngLat.lng } });
      }
    });

    state.map.on('load', () => {
      addMacerataBoundaryLayer();
      setStatus(`Mappa gratuita OSM pronta. Limite immagine: ${config.maxImageSizeMb}MB.`);
    });
  }

  // applyCityZoomConstraints was specific to Leaflet and is no longer needed with MapLibre.
  function applyCityZoomConstraints() {
    // no-op
  }

  function leafletBoundsFromBoundaryFeature(boundaryFeature) {
    // no longer used with MapLibre; kept for reference
    return null;
  }

  function leafletBoundsFromApi(apiBounds) {
    // no longer used with MapLibre; convert to array of 2 coordinate pairs
    if (!apiBounds || !Array.isArray(apiBounds) || apiBounds.length < 2) return null;
    return [
      [apiBounds[0][0], apiBounds[0][1]],
      [apiBounds[1][0], apiBounds[1][1]],
    ];
  }

  // MapLibre GL styles for different modes
  function getMapLibreStyle(mode) {
    if (mode === 'satellite') {
      return 'https://demotiles.maplibre.org/style.json'; // placeholder; replace with actual satellite style if desired
    }
    // standard OSM-style vector tiles
    return 'https://demotiles.maplibre.org/style.json';
  }

  function setMapMode(mode, options = {}) {
    if (!state.map) {
      return;
    }
    if (state.currentMapMode === mode) {
      return;
    }

    state.currentMapMode = mode;
    updateModeButtons();

    const newStyle = getMapLibreStyle(mode);
    state.map.setStyle(newStyle);

    closeActivePopup();

    if (!options.silentStatus) {
      setStatus(`Vista "${modeLabel(mode)}" attivata.`);
    }
  }

  function updateModeButtons() {
    elements.modeButtons.forEach((button) => {
      button.classList.toggle('is-active', button.dataset.mode === state.currentMapMode);
    });
  }

  function modeLabel(mode) {
    if (mode === 'satellite') {
      return 'Satellitare';
    }
    return 'Semplice';
  }

  function addMacerataBoundaryLayer() {
    if (!state.map || !state.mapConfig || !state.mapConfig.macerata.boundary) {
      return;
    }

    const sourceId = 'macerata-boundary';
    if (state.map.getSource(sourceId)) {
      state.map.getSource(sourceId).setData(state.mapConfig.macerata.boundary);
    } else {
      state.map.addSource(sourceId, { type: 'geojson', data: state.mapConfig.macerata.boundary });
      state.map.addLayer({
        id: sourceId + '-line',
        type: 'line',
        source: sourceId,
        paint: {
          'line-color': '#ff304f',
          'line-width': 3.5,
        },
      });
    }
  }

  // world mask not needed with MapLibre; function kept as stub
  function createWorldMaskLayer(boundaryFeature) {
    return null;
  }

  function extractGeometryOuterRings(geometry) {
    if (!geometry || !geometry.type || !Array.isArray(geometry.coordinates)) {
      return [];
    }

    if (geometry.type === 'Polygon') {
      return geometry.coordinates.length ? [geometry.coordinates[0]] : [];
    }

    if (geometry.type === 'MultiPolygon') {
      return geometry.coordinates
        .map((polygon) => (Array.isArray(polygon) && polygon.length ? polygon[0] : null))
        .filter(Boolean);
    }

    return [];
  }

  async function loadPins() {
    if (!state.map) {
      return;
    }

    const pins = await apiFetch('/api/pins');
    clearAllMarkers();
    pins.forEach((pin) => upsertPinMarker(pin));
  }

  function clearAllMarkers() {
    state.markers.forEach((entry) => entry.marker.remove());
    state.markers.clear();
    state.activePopupPinId = null;
  }

  function createPinIcon() {
    const el = document.createElement('div');
    el.className = 'pin-marker-icon';
    el.innerHTML = '<span class="pin-marker-dot" aria-hidden="true"></span>';
    el.style.width = '22px';
    el.style.height = '22px';
    return el;
  }

  function createPickIcon() {
    const el = document.createElement('div');
    el.className = 'map-pick-icon';
    el.innerHTML = '<span class="map-pick-dot" aria-hidden="true"></span>';
    el.style.width = '20px';
    el.style.height = '20px';
    return el;
  }

  function upsertPinMarker(pin) {
    const existing = state.markers.get(pin.id);
    if (existing) {
      existing.pin = pin;
      existing.marker.setLngLat([pin.lng, pin.lat]);
      return;
    }

    const el = createPinIcon();
    const marker = new maplibregl.Marker({ element: el, draggable: false })
      .setLngLat([pin.lng, pin.lat])
      .addTo(state.map);

    const popup = new maplibregl.Popup({
      closeButton: false,
      closeOnClick: false,
      className: 'pin-popup',
      offset: 25,
    }).setDOMContent(buildPinPopupContent(pin));

    marker.getElement().addEventListener('click', (e) => {
      e.stopPropagation();
      openPinPopup(pin.id);
    });

    const markerEntry = { marker, popup, pin };
    state.markers.set(pin.id, markerEntry);
  }

  function removePinMarker(pinId) {
    const entry = state.markers.get(pinId);
    if (!entry) {
      return;
    }

    entry.marker.remove();
    if (entry.popup) entry.popup.remove();
    state.markers.delete(pinId);
    if (state.activePopupPinId === pinId) {
      state.activePopupPinId = null;
    }
  }

  function closeActivePopup() {
    if (!state.activePopupPinId) {
      return;
    }

    closePopupByPinId(state.activePopupPinId);
  }

  function closePopupByPinId(pinId) {
    const entry = state.markers.get(pinId);
    if (!entry || !entry.popup) {
      return;
    }

    entry.popup.remove();
    if (state.activePopupPinId === pinId) {
      state.activePopupPinId = null;
    }
  }

  function closeAllPinPopups(exceptPinId = null) {
    state.markers.forEach((entry, markerPinId) => {
      if (exceptPinId !== null && markerPinId === exceptPinId) {
        return;
      }
      if (entry.popup) entry.popup.remove();
    });

    if (exceptPinId === null) {
      state.activePopupPinId = null;
    }
  }

  function openPinPopup(pinId) {
    const entry = state.markers.get(pinId);
    if (!entry || !entry.popup) {
      return;
    }

    closeAllPinPopups(pinId);

    entry.popup.setLngLat(entry.marker.getLngLat()).addTo(state.map);
    state.activePopupPinId = pinId;
  }

  function buildPinPopupContent(pin) {
    const root = document.createElement('article');
    root.className = 'pin-card';

    const top = document.createElement('div');
    top.className = 'pin-card-top';

    const infoWrap = document.createElement('div');
    const title = document.createElement('h4');
    title.textContent = 'Foto';
    const subtitle = document.createElement('p');
    subtitle.textContent = pin.createdAtFormatted;
    infoWrap.appendChild(title);
    infoWrap.appendChild(subtitle);

    const closeButton = document.createElement('button');
    closeButton.type = 'button';
    closeButton.className = 'pin-close';
    closeButton.innerHTML = '&times;';
    closeButton.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopPropagation();
      closePopupByPinId(pin.id);
    });

    top.appendChild(infoWrap);
    top.appendChild(closeButton);

    const address = document.createElement('p');
    address.textContent = pin.address;

    const image = document.createElement('img');
    image.className = 'pin-image';
    image.src = pin.imageUrl;
    image.alt = `Foto pin ${pin.id}`;
    image.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopPropagation();
      if (Date.now() < state.fullscreenGuardUntil) {
        return;
      }
      openFullscreen(pin.imageUrl, pin.address);
    });

    root.appendChild(top);
    root.appendChild(address);
    root.appendChild(image);

    if (state.isAuthenticated) {
      const actions = document.createElement('div');
      actions.className = 'pin-actions';

      const replaceButton = document.createElement('button');
      replaceButton.type = 'button';
      replaceButton.textContent = 'Sostituisci';
      replaceButton.addEventListener('click', () => {
        state.replacePinId = pin.id;
        elements.replaceImageInput.click();
      });

      const moveButton = document.createElement('button');
      moveButton.type = 'button';
      moveButton.textContent = 'Sposta';
      moveButton.addEventListener('click', () => {
        startMovePin(pin.id);
      });

      const deleteButton = document.createElement('button');
      deleteButton.type = 'button';
      deleteButton.className = 'danger';
      deleteButton.textContent = 'Elimina';
      deleteButton.addEventListener('click', () => {
        deletePin(pin.id);
      });

      actions.appendChild(replaceButton);
      actions.appendChild(moveButton);
      actions.appendChild(deleteButton);
      root.appendChild(actions);
    } else {
      const readonlyNote = document.createElement('p');
      readonlyNote.className = 'pin-readonly-note';
      readonlyNote.textContent = 'Accedi per modificare o eliminare questo pin.';
      root.appendChild(readonlyNote);
    }

    return root;
  }

  function openFullscreen(imageUrl, caption) {
    elements.fullscreenImage.src = imageUrl;
    elements.fullscreenCaption.textContent = caption || '';
    elements.fullscreenOverlay.classList.remove('is-hidden');
  }

  function closeFullscreen() {
    state.fullscreenGuardUntil = Date.now() + 260;
    elements.fullscreenOverlay.classList.add('is-hidden');
    elements.fullscreenImage.src = '';
    elements.fullscreenCaption.textContent = '';
  }

  async function startUploadFlow(file) {
    if (!ensureAuthenticatedForEdit('caricare immagini')) {
      return;
    }

    if (!state.map) {
      setStatus('Mappa non pronta.', 'error');
      return;
    }

    if (state.moveState) {
      showToast('Completa o annulla prima lo spostamento pin attivo.', true);
      return;
    }

    if (file.size > state.maxImageSizeBytes) {
      const maxMb = Math.floor(state.maxImageSizeBytes / (1024 * 1024));
      showToast(`Immagine troppo grande. Limite ${maxMb} MB.`, true);
      return;
    }

    try {
      setStatus('Lettura metadati foto in corso...');
      const exifPosition = await readExifGps(file);

      if (exifPosition) {
        setStatus(`Metadati GPS trovati (${exifPosition.lat.toFixed(6)}, ${exifPosition.lng.toFixed(6)}). Verifica posizione...`);
        const check = await checkLocationInsideMacerata(exifPosition.lat, exifPosition.lng);
        if (check.inside) {
          const choice = await showChoiceDialog({
            title: 'Posizione EXIF trovata',
            message: 'Usare la posizione di scatto rilevata dalla foto?',
            choices: [
              { label: 'Usa posizione EXIF', value: 'use', primary: true },
              { label: 'Scegli manualmente', value: 'manual' },
            ],
          });

          if (choice === 'use') {
            await createPinFromFile(file, exifPosition.lat, exifPosition.lng);
            return;
          }
        } else {
          showToast('Posizione EXIF fuori Macerata: scegli manualmente.');
        }
      } else {
        setStatus('Nessun GPS nei metadati: scegli posizione manualmente.');
      }

      await runManualPlacementFlow(file);
    } catch (error) {
      showToast(error.message || 'Errore durante il caricamento', true);
      setStatus(error.message || 'Errore durante il caricamento', 'error');
    }
  }

  async function runManualPlacementFlow(file) {
    const method = await showChoiceDialog({
      title: 'Seleziona posizione',
      message: 'Come vuoi inserire il punto della foto?',
      choices: [
        { label: 'Inserisci via e civico', value: 'address', primary: true },
        { label: 'Seleziona su mappa', value: 'map' },
        { label: 'Annulla', value: 'cancel' },
      ],
    });

    if (method === 'address') {
      await placePinByAddress(file);
    } else if (method === 'map') {
      startMapPickMode(file);
    }
  }

  async function placePinByAddress(file) {
    const selectedAddress = await showAddressAutocompleteDialog();
    if (!selectedAddress) {
      return;
    }

    try {
      setStatus('Ricerca indirizzo...');
      const confirm = await showChoiceDialog({
        title: 'Conferma posizione',
        message: selectedAddress.address,
        choices: [
          { label: 'Conferma e carica', value: 'confirm', primary: true },
          { label: 'Annulla', value: 'cancel' },
        ],
      });

      if (confirm === 'confirm') {
        await createPinFromFile(file, selectedAddress.lat, selectedAddress.lng);
      }
    } catch (error) {
      showToast(error.message || 'Nessun indirizzo trovato', true);
      setStatus(error.message || 'Nessun indirizzo trovato', 'error');
    }
  }

  function startMapPickMode(file) {
    state.mapPickMode = true;
    state.mapPickFile = file;
    state.mapPickBusy = false;
    elements.mapPickBanner.classList.remove('is-hidden');
    elements.map.classList.add('map-pick-mode');
    setStatus('Selezione attiva: clicca la posizione sulla mappa.');
  }

  function stopMapPickMode() {
    state.mapPickMode = false;
    state.mapPickFile = null;
    state.mapPickBusy = false;
    elements.mapPickBanner.classList.add('is-hidden');
    elements.map.classList.remove('map-pick-mode');

    if (state.mapPickMarker) {
      state.map.removeLayer(state.mapPickMarker);
      state.mapPickMarker = null;
    }
  }

  async function onMapPickClick(latlng) {
    if (!state.mapPickMode || !state.mapPickFile || state.mapPickBusy) {
      return;
    }

    state.mapPickBusy = true;
    try {
      const lat = latlng.lat;
      const lng = latlng.lng;
      const check = await checkLocationInsideMacerata(lat, lng);

      if (!check.inside) {
        showToast('Punto fuori Macerata, selezionane uno interno.', true);
        return;
      }

      if (state.mapPickMarker) {
        state.map.removeLayer(state.mapPickMarker);
      }

      if (state.mapPickMarker) {
        state.mapPickMarker.remove();
      }
      const pickEl = createPickIcon();
      state.mapPickMarker = new maplibregl.Marker({ element: pickEl, draggable: false })
        .setLngLat([lng, lat])
        .addTo(state.map);

      const decision = await showChoiceDialog({
        title: 'Usare questo punto?',
        message: check.address || 'Posizione selezionata sulla mappa',
        choices: [
          { label: 'Conferma punto', value: 'confirm', primary: true },
          { label: 'Scegli un altro punto', value: 'again' },
          { label: 'Annulla', value: 'cancel' },
        ],
      });

      if (decision === 'confirm') {
        const file = state.mapPickFile;
        stopMapPickMode();
        await createPinFromFile(file, lat, lng);
      } else if (decision === 'cancel') {
        stopMapPickMode();
        setStatus('Selezione annullata.');
      }
    } catch (error) {
      showToast(error.message || 'Errore durante selezione da mappa', true);
      setStatus(error.message || 'Errore durante selezione da mappa', 'error');
    } finally {
      state.mapPickBusy = false;
    }
  }

  async function createPinFromFile(file, lat, lng) {
    const imagePayload = await fileToImagePayload(file);
    const created = await apiFetch('/api/pins', {
      method: 'POST',
      body: {
        lat,
        lng,
        image: imagePayload,
      },
    });

    upsertPinMarker(created);
    state.map.flyTo([created.lat, created.lng], Math.max(state.map.getZoom(), 14.5), {
      duration: 0.8,
    });
    setStatus('Pin creato con successo.', 'success');
    showToast('Foto caricata e pin creato');
  }

  async function replacePinImage(pinId, file) {
    if (!ensureAuthenticatedForEdit('modificare i pin')) {
      return;
    }

    try {
      if (file.size > state.maxImageSizeBytes) {
        const maxMb = Math.floor(state.maxImageSizeBytes / (1024 * 1024));
        showToast(`Immagine troppo grande. Limite ${maxMb} MB.`, true);
        return;
      }

      const imagePayload = await fileToImagePayload(file);
      const updated = await apiFetch(`/api/pins/${pinId}`, {
        method: 'PATCH',
        body: { image: imagePayload },
      });

      upsertPinMarker(updated);
      openPinPopup(pinId);
      setStatus('Immagine pin aggiornata.', 'success');
      showToast('Immagine sostituita');
    } catch (error) {
      showToast(error.message || 'Errore durante sostituzione immagine', true);
      setStatus(error.message || 'Errore durante sostituzione immagine', 'error');
    }
  }

  async function deletePin(pinId) {
    if (!ensureAuthenticatedForEdit('eliminare i pin')) {
      return;
    }

    const confirm = await showChoiceDialog({
      title: 'Elimina pin',
      message: 'Confermi eliminazione definitiva di questa foto?',
      choices: [
        { label: 'Elimina', value: 'delete', primary: true },
        { label: 'Annulla', value: 'cancel' },
      ],
    });

    if (confirm !== 'delete') {
      return;
    }

    try {
      await apiFetch(`/api/pins/${pinId}`, { method: 'DELETE' });
      removePinMarker(pinId);
      setStatus('Pin eliminato.', 'success');
      showToast('Pin eliminato');
    } catch (error) {
      showToast(error.message || 'Errore durante eliminazione pin', true);
      setStatus(error.message || 'Errore durante eliminazione pin', 'error');
    }
  }

  function startMovePin(pinId) {
    if (!ensureAuthenticatedForEdit('spostare i pin')) {
      return;
    }

    if (state.mapPickMode) {
      showToast('Annulla prima la selezione da mappa in corso.', true);
      return;
    }

    if (state.moveState && state.moveState.pinId !== pinId) {
      showToast('Completa prima lo spostamento gia attivo.', true);
      return;
    }

    const entry = state.markers.get(pinId);
    if (!entry) {
      return;
    }

    closeActivePopup();

    const current = entry.marker.getLatLng();
    state.moveState = {
      pinId,
      originalLat: current.lat,
      originalLng: current.lng,
    };

    entry.marker.dragging.enable();
    setMarkerMoveVisual(entry.marker, true);
    elements.moveToolbar.classList.remove('is-hidden');
    setStatus('Trascina il pin e poi clicca "Salva posizione".');
  }

  async function saveMovePinPosition() {
    if (!ensureAuthenticatedForEdit('spostare i pin')) {
      return;
    }

    if (!state.moveState) {
      return;
    }

    const { pinId } = state.moveState;
    const entry = state.markers.get(pinId);
    if (!entry) {
      resetMoveState();
      return;
    }

    try {
      const moved = entry.marker.getLatLng();
      const check = await checkLocationInsideMacerata(moved.lat, moved.lng);
      if (!check.inside) {
        showToast('Posizione fuori Macerata: spostamento annullato.', true);
        cancelMovePinPosition();
        return;
      }

      const updated = await apiFetch(`/api/pins/${pinId}`, {
        method: 'PATCH',
        body: {
          lat: moved.lat,
          lng: moved.lng,
        },
      });

      entry.marker.dragging.disable();
      setMarkerMoveVisual(entry.marker, false);
      upsertPinMarker(updated);
      resetMoveState();
      openPinPopup(pinId);
      setStatus('Posizione pin aggiornata.', 'success');
      showToast('Posizione salvata');
    } catch (error) {
      showToast(error.message || 'Errore durante aggiornamento posizione', true);
      setStatus(error.message || 'Errore durante aggiornamento posizione', 'error');
    }
  }

  function cancelMovePinPosition() {
    if (!state.moveState) {
      return;
    }

    const { pinId, originalLat, originalLng } = state.moveState;
    const entry = state.markers.get(pinId);
    if (entry) {
      entry.marker.setLatLng([originalLat, originalLng]);
      entry.marker.dragging.disable();
      setMarkerMoveVisual(entry.marker, false);
    }

    resetMoveState();
    setStatus('Spostamento annullato.');
  }

  function resetMoveState() {
    state.moveState = null;
    elements.moveToolbar.classList.add('is-hidden');
  }

  function setMarkerMoveVisual(marker, moving) {
    const markerEl = marker.getElement();
    if (!markerEl) {
      return;
    }

    markerEl.classList.toggle('is-moving', moving);
  }

  async function checkLocationInsideMacerata(lat, lng) {
    return apiFetch(`/api/location-check?lat=${encodeURIComponent(lat)}&lng=${encodeURIComponent(lng)}`);
  }

  async function readExifGps(file) {
    if (!window.exifr) {
      return null;
    }

    const candidates = [];
    const pushCandidate = (value) => {
      if (value && typeof value === 'object') {
        candidates.push(value);
      }
    };

    try {
      const gps = window.exifr.gps ? await window.exifr.gps(file) : null;
      pushCandidate(gps);
    } catch (_error) {
      // Ignora, provo parse completo.
    }

    try {
      const parsed = window.exifr.parse ? await window.exifr.parse(file, {
        gps: true,
        exif: true,
        xmp: true,
        tiff: true,
        ifd0: true,
        interop: true,
        translateValues: false,
      }) : null;
      pushCandidate(parsed);
    } catch (_error) {
      // Ignora, provo parse senza filtri.
    }

    try {
      const parsedAny = window.exifr.parse ? await window.exifr.parse(file, {
        translateValues: false,
      }) : null;
      pushCandidate(parsedAny);
    } catch (_error) {
      // Ignore.
    }

    for (const source of candidates) {
      const position = extractExifPosition(source);
      if (position) {
        return position;
      }
    }

    return null;
  }

  function extractExifPosition(source) {
    if (!source || typeof source !== 'object') {
      return null;
    }

    const gpsContainer = firstDefined(
      source.GPS,
      source.gps,
      source.GPSInfo,
      source.exif && source.exif.GPS,
      source.Exif && source.Exif.GPS,
    );

    const pairCandidates = [
      source.GPSPosition,
      source.position,
      source.Position,
      source.coordinates,
      source.Coordinates,
      source.location,
      source.Location,
      source.GPSCoordinates,
      source['GPS:Position'],
      gpsContainer && gpsContainer.GPSPosition,
      gpsContainer && gpsContainer.position,
      gpsContainer && gpsContainer.coordinates,
    ];

    for (const pairCandidate of pairCandidates) {
      const parsedPair = parseCoordinatePairValue(pairCandidate);
      if (parsedPair) {
        return parsedPair;
      }
    }

    const latRef = firstDefined(
      source.GPSLatitudeRef,
      source.LatitudeRef,
      source.GPSLatRef,
      source['GPS:LatitudeRef'],
      gpsContainer && gpsContainer.GPSLatitudeRef,
      gpsContainer && gpsContainer.LatitudeRef,
      gpsContainer && gpsContainer.GPSLatRef,
      gpsContainer && gpsContainer['GPS:LatitudeRef'],
    );

    const lngRef = firstDefined(
      source.GPSLongitudeRef,
      source.LongitudeRef,
      source.GPSLngRef,
      source.GPSLonRef,
      source['GPS:LongitudeRef'],
      gpsContainer && gpsContainer.GPSLongitudeRef,
      gpsContainer && gpsContainer.LongitudeRef,
      gpsContainer && gpsContainer.GPSLngRef,
      gpsContainer && gpsContainer.GPSLonRef,
      gpsContainer && gpsContainer['GPS:LongitudeRef'],
    );

    const latValue = firstDefined(
      source.latitude,
      source.lat,
      source.GPSLatitude,
      source.GPSLat,
      source['GPS:Latitude'],
      gpsContainer && gpsContainer.latitude,
      gpsContainer && gpsContainer.lat,
      gpsContainer && gpsContainer.GPSLatitude,
      gpsContainer && gpsContainer.GPSLat,
      gpsContainer && gpsContainer['GPS:Latitude'],
    );

    const lngValue = firstDefined(
      source.longitude,
      source.lng,
      source.lon,
      source.GPSLongitude,
      source.GPSLongitudeRefValue,
      source.GPSLng,
      source.GPSLon,
      source['GPS:Longitude'],
      gpsContainer && gpsContainer.longitude,
      gpsContainer && gpsContainer.lng,
      gpsContainer && gpsContainer.lon,
      gpsContainer && gpsContainer.GPSLongitude,
      gpsContainer && gpsContainer.GPSLng,
      gpsContainer && gpsContainer.GPSLon,
      gpsContainer && gpsContainer['GPS:Longitude'],
    );

    return normalizeCoordinatePair(latValue, latRef, lngValue, lngRef);
  }

  function parseCoordinatePairValue(value) {
    if (!value) {
      return null;
    }

    if (Array.isArray(value) && value.length >= 2) {
      return sanitizeLatLng(
        normalizeExifCoordinate(value[0], null),
        normalizeExifCoordinate(value[1], null),
      );
    }

    if (typeof value === 'object') {
      const directPair = sanitizeLatLng(
        normalizeExifCoordinate(firstDefined(value.lat, value.latitude, value.y), value.latRef || value.latitudeRef),
        normalizeExifCoordinate(firstDefined(value.lng, value.lon, value.longitude, value.x), value.lngRef || value.lonRef || value.longitudeRef),
      );
      if (directPair) {
        return directPair;
      }

      if (value.GPSLatitude !== undefined || value.GPSLongitude !== undefined) {
        return normalizeCoordinatePair(
          value.GPSLatitude,
          value.GPSLatitudeRef,
          value.GPSLongitude,
          value.GPSLongitudeRef,
        );
      }
    }

    if (typeof value === 'string') {
      return parseCoordinatePairString(value);
    }

    return null;
  }

  function parseCoordinatePairString(text) {
    const raw = String(text || '').trim();
    if (!raw) {
      return null;
    }

    const numbers = raw.match(/-?\d+(?:[.,]\d+)?/g);
    if (!numbers || numbers.length < 2) {
      return null;
    }

    const latRef = raw.match(/[NS]/i)?.[0] || null;
    const lngRef = raw.match(/[EW]/i)?.[0] || null;

    if (numbers.length >= 6 && (latRef || lngRef)) {
      const lat = dmsToDecimal(numbers.slice(0, 3));
      const lng = dmsToDecimal(numbers.slice(3, 6));
      return sanitizeLatLng(applyCoordinateRef(lat, latRef), applyCoordinateRef(lng, lngRef));
    }

    const lat = Number.parseFloat(String(numbers[0]).replace(',', '.'));
    const lng = Number.parseFloat(String(numbers[1]).replace(',', '.'));
    return sanitizeLatLng(applyCoordinateRef(lat, latRef), applyCoordinateRef(lng, lngRef));
  }

  function normalizeCoordinatePair(latValue, latRef, lngValue, lngRef) {
    const lat = normalizeExifCoordinate(latValue, latRef);
    const lng = normalizeExifCoordinate(lngValue, lngRef);
    return sanitizeLatLng(lat, lng);
  }

  function sanitizeLatLng(lat, lng) {
    if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
      return null;
    }

    let normalizedLat = Number(lat);
    let normalizedLng = Number(lng);

    if (Math.abs(normalizedLat) > 90 && Math.abs(normalizedLng) <= 90) {
      const swapped = normalizedLat;
      normalizedLat = normalizedLng;
      normalizedLng = swapped;
    }

    if (Math.abs(normalizedLat) > 90 || Math.abs(normalizedLng) > 180) {
      return null;
    }

    return { lat: normalizedLat, lng: normalizedLng };
  }

  function applyCoordinateRef(value, ref) {
    if (!Number.isFinite(value)) {
      return null;
    }

    const refText = String(ref || '').trim().toUpperCase();
    if ((refText === 'S' || refText === 'W') && value > 0) {
      return -value;
    }
    return value;
  }

  function firstDefined(...values) {
    for (const value of values) {
      if (value !== undefined && value !== null) {
        return value;
      }
    }
    return null;
  }

  function normalizeExifCoordinate(value, ref) {
    let numeric = null;
    let derivedRef = ref;

    if (typeof value === 'number' && Number.isFinite(value)) {
      numeric = value;
    } else if (typeof value === 'string') {
      const parsedFromString = parseExifCoordinateString(value);
      numeric = parsedFromString.value;
      if (!derivedRef && parsedFromString.ref) {
        derivedRef = parsedFromString.ref;
      }
    } else if (Array.isArray(value) && value.length >= 1) {
      numeric = dmsToDecimal(value);
    } else if (value && typeof value === 'object') {
      if (Number.isFinite(value.latitude) || Number.isFinite(value.longitude)) {
        numeric = Number.isFinite(value.latitude) ? Number(value.latitude) : Number(value.longitude);
      } else if (Number.isFinite(value.degrees) || Number.isFinite(value.minutes) || Number.isFinite(value.seconds)) {
        numeric = dmsToDecimal([value.degrees || 0, value.minutes || 0, value.seconds || 0]);
      }
    }

    if (!Number.isFinite(numeric)) {
      return null;
    }

    return applyCoordinateRef(numeric, derivedRef);
  }

  function parseExifCoordinateString(value) {
    const raw = String(value || '').trim();
    if (!raw) {
      return { value: null, ref: null };
    }

    const refMatch = raw.match(/[NSEW]/i);
    const derivedRef = refMatch ? refMatch[0].toUpperCase() : null;

    const numericParts = raw.match(/-?\d+(?:[.,]\d+)?/g);
    if (!numericParts || !numericParts.length) {
      return { value: null, ref: derivedRef };
    }

    if (numericParts.length >= 3 && (raw.includes("'") || raw.includes('"') || raw.includes('deg'))) {
      const dms = dmsToDecimal(numericParts.slice(0, 3));
      return { value: dms, ref: derivedRef };
    }

    const decimal = Number.parseFloat(String(numericParts[0]).replace(',', '.'));
    return {
      value: Number.isFinite(decimal) ? decimal : null,
      ref: derivedRef,
    };
  }

  function dmsToDecimal(parts) {
    if (!Array.isArray(parts) || parts.length < 1) {
      return null;
    }

    const degrees = toNumber(parts[0]);
    const minutes = toNumber(parts[1] || 0);
    const seconds = toNumber(parts[2] || 0);

    if (![degrees, minutes, seconds].every(Number.isFinite)) {
      return null;
    }

    const sign = degrees < 0 ? -1 : 1;
    const absDegrees = Math.abs(degrees);
    return sign * (absDegrees + (Math.abs(minutes) / 60) + (Math.abs(seconds) / 3600));
  }

  function toNumber(value) {
    if (typeof value === 'number') {
      return value;
    }

    if (typeof value === 'string') {
      const parsed = Number.parseFloat(value.replace(',', '.'));
      return Number.isFinite(parsed) ? parsed : null;
    }

    if (value && typeof value === 'object') {
      if (Number.isFinite(value.numerator) && Number.isFinite(value.denominator) && value.denominator !== 0) {
        return value.numerator / value.denominator;
      }
      if (Number.isFinite(value.value)) {
        return Number(value.value);
      }
    }

    return null;
  }

  function fileToImagePayload(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onerror = () => reject(new Error('Impossibile leggere il file immagine'));
      reader.onload = () => {
        const result = String(reader.result || '');
        const splitIndex = result.indexOf(',');
        const base64 = splitIndex >= 0 ? result.slice(splitIndex + 1) : result;
        resolve({
          name: file.name,
          type: file.type,
          size: file.size,
          base64,
        });
      };
      reader.readAsDataURL(file);
    });
  }

  async function apiFetch(url, options = {}) {
    const {
      body,
      headers,
      skipAuthHandling = false,
      ...rest
    } = options;

    const requestOptions = {
      credentials: 'include',
      ...rest,
      headers: {
        ...(headers || {}),
      },
    };

    if (body !== undefined) {
      requestOptions.body = JSON.stringify(body);
      requestOptions.headers['Content-Type'] = 'application/json';
    }

    const response = await fetch(url, requestOptions);
    const contentType = response.headers.get('content-type') || '';
    const isJson = contentType.includes('application/json');
    const payload = isJson ? await response.json() : null;

    if (!response.ok) {
      if (response.status === 401 && !skipAuthHandling) {
        state.isAuthenticated = false;
        setAuthUiState();
        openAuthOverlay();
        setStatus('Accesso richiesto per questa operazione.', 'error');
      }

      const message = payload && payload.error ? payload.error : `Errore HTTP ${response.status}`;
      throw new Error(message);
    }

    return payload;
  }

  function showToast(message, isError = false) {
    elements.toast.textContent = message;
    elements.toast.classList.remove('is-hidden');
    elements.toast.classList.toggle('is-error', isError);

    if (state.toastTimer) {
      clearTimeout(state.toastTimer);
    }

    state.toastTimer = setTimeout(() => {
      elements.toast.classList.add('is-hidden');
      elements.toast.classList.remove('is-error');
    }, 3000);
  }

  function setStatus(message, tone = 'info') {
    elements.statusLine.textContent = message;
    elements.statusLine.classList.remove('is-error', 'is-success');
    if (tone === 'error') {
      elements.statusLine.classList.add('is-error');
    } else if (tone === 'success') {
      elements.statusLine.classList.add('is-success');
    }
  }

  function showChoiceDialog({ title, message, choices }) {
    return showDialog({ title, message, choices }).then((result) => (result ? result.value : null));
  }

  function fetchAddressSuggestions(query, limit = 7) {
    return apiFetch(`/api/geocode/suggest?q=${encodeURIComponent(query)}&limit=${encodeURIComponent(limit)}`);
  }

  function showAddressAutocompleteDialog() {
    if (state.dialogResolver) {
      resolveDialog(null);
    }

    elements.dialogTitle.textContent = 'Inserisci indirizzo';
    elements.dialogMessage.textContent = 'Scrivi via e numero civico: vedrai i suggerimenti mentre scrivi.';
    elements.dialogInputWrap.classList.remove('is-hidden');
    elements.dialogInputLabel.textContent = 'Via e civico';
    elements.dialogInput.value = '';
    elements.dialogInput.placeholder = 'Esempio: Via Roma 21';
    elements.dialogButtons.innerHTML = '';

    const suggestionsWrap = document.createElement('div');
    suggestionsWrap.className = 'address-suggestions';

    const helperText = document.createElement('p');
    helperText.className = 'address-helper';
    helperText.textContent = 'Scrivi almeno 2 caratteri.';

    elements.dialogInputWrap.appendChild(suggestionsWrap);
    elements.dialogInputWrap.appendChild(helperText);

    const confirmButton = document.createElement('button');
    confirmButton.type = 'button';
    confirmButton.textContent = 'Usa indirizzo';
    confirmButton.classList.add('primary');

    const cancelButton = document.createElement('button');
    cancelButton.type = 'button';
    cancelButton.textContent = 'Annulla';

    elements.dialogButtons.appendChild(confirmButton);
    elements.dialogButtons.appendChild(cancelButton);

    let suggestions = [];
    let selectedIndex = -1;
    let selectedResult = null;
    let debounceTimer = null;
    let requestSequence = 0;

    const cleanup = () => {
      if (debounceTimer) {
        clearTimeout(debounceTimer);
      }
      elements.dialogInput.removeEventListener('input', onInput);
      elements.dialogInput.removeEventListener('keydown', onKeyDown);
      confirmButton.removeEventListener('click', onConfirm);
      cancelButton.removeEventListener('click', onCancel);
      suggestionsWrap.remove();
      helperText.remove();
    };

    const setSelection = (index) => {
      if (index < 0 || index >= suggestions.length) {
        selectedIndex = -1;
        selectedResult = null;
      } else {
        selectedIndex = index;
        selectedResult = suggestions[index];
      }
      renderSuggestions();
    };

    const renderSuggestions = () => {
      suggestionsWrap.innerHTML = '';

      if (!suggestions.length) {
        return;
      }

      suggestions.forEach((item, index) => {
        const suggestionButton = document.createElement('button');
        suggestionButton.type = 'button';
        suggestionButton.className = 'address-suggestion';
        if (index === selectedIndex) {
          suggestionButton.classList.add('is-active');
        }

        const parts = String(item.address || '').split(',').map((part) => part.trim()).filter(Boolean);
        const primary = document.createElement('span');
        primary.className = 'address-primary';
        primary.textContent = parts.slice(0, 2).join(', ') || item.address;

        const secondary = document.createElement('span');
        secondary.className = 'address-secondary';
        secondary.textContent = parts.slice(2).join(', ');

        suggestionButton.appendChild(primary);
        if (secondary.textContent) {
          suggestionButton.appendChild(secondary);
        }

        suggestionButton.addEventListener('click', () => {
          setSelection(index);
          elements.dialogInput.value = item.address;
          elements.dialogInput.focus();
        });

        suggestionsWrap.appendChild(suggestionButton);
      });
    };

    const runSuggestSearch = async (rawText) => {
      const text = String(rawText || '').trim();
      selectedResult = null;
      selectedIndex = -1;

      if (text.length < 2) {
        suggestions = [];
        helperText.textContent = 'Scrivi almeno 2 caratteri.';
        renderSuggestions();
        return;
      }

      const currentRequest = ++requestSequence;
      helperText.textContent = 'Ricerca suggerimenti...';

      try {
        const results = await fetchAddressSuggestions(text, 7);
        if (currentRequest !== requestSequence) {
          return;
        }

        suggestions = Array.isArray(results) ? results : [];
        if (suggestions.length > 0) {
          helperText.textContent = `${suggestions.length} suggerimenti trovati.`;
          selectedIndex = 0;
          selectedResult = suggestions[0];
        } else {
          helperText.textContent = 'Nessun suggerimento trovato.';
        }

        renderSuggestions();
      } catch (_error) {
        if (currentRequest !== requestSequence) {
          return;
        }
        suggestions = [];
        helperText.textContent = 'Errore durante la ricerca suggerimenti.';
        renderSuggestions();
      }
    };

    const onInput = () => {
      if (debounceTimer) {
        clearTimeout(debounceTimer);
      }
      debounceTimer = setTimeout(() => {
        runSuggestSearch(elements.dialogInput.value);
      }, 260);
    };

    const onKeyDown = (event) => {
      if (!suggestions.length) {
        return;
      }

      if (event.key === 'ArrowDown') {
        event.preventDefault();
        const nextIndex = selectedIndex < suggestions.length - 1 ? selectedIndex + 1 : 0;
        setSelection(nextIndex);
      } else if (event.key === 'ArrowUp') {
        event.preventDefault();
        const nextIndex = selectedIndex > 0 ? selectedIndex - 1 : suggestions.length - 1;
        setSelection(nextIndex);
      } else if (event.key === 'Enter') {
        event.preventDefault();
        onConfirm();
      }
    };

    const resolveAndClose = (value) => {
      resolveDialog(value);
    };

    const onCancel = () => {
      resolveAndClose(null);
    };

    const onConfirm = async () => {
      try {
        let result = selectedResult;
        const typed = String(elements.dialogInput.value || '').trim();

        if (!result && !typed) {
          helperText.textContent = 'Inserisci un indirizzo.';
          return;
        }

        confirmButton.disabled = true;
        if (!result) {
          helperText.textContent = 'Ricerca indirizzo...';
          result = await apiFetch('/api/geocode', {
            method: 'POST',
            body: { address: typed },
          });
        }

        resolveAndClose(result);
      } catch (error) {
        helperText.textContent = error.message || 'Indirizzo non valido.';
      } finally {
        confirmButton.disabled = false;
      }
    };

    elements.dialogInput.addEventListener('input', onInput);
    elements.dialogInput.addEventListener('keydown', onKeyDown);
    confirmButton.addEventListener('click', onConfirm);
    cancelButton.addEventListener('click', onCancel);
    elements.dialogOverlay.classList.remove('is-hidden');
    elements.dialogInput.focus();

    return new Promise((resolve) => {
      state.dialogResolver = (value) => {
        cleanup();
        resolve(value);
      };
    });
  }

  function showDialog({
    title,
    message,
    choices,
    input = null,
  }) {
    if (state.dialogResolver) {
      resolveDialog(null);
    }

    elements.dialogTitle.textContent = title || '';
    elements.dialogMessage.textContent = message || '';
    elements.dialogButtons.innerHTML = '';

    if (input) {
      elements.dialogInputWrap.classList.remove('is-hidden');
      elements.dialogInputLabel.textContent = input.label || '';
      elements.dialogInput.value = '';
      elements.dialogInput.placeholder = input.placeholder || '';
    } else {
      elements.dialogInputWrap.classList.add('is-hidden');
      elements.dialogInput.value = '';
      elements.dialogInput.placeholder = '';
    }

    choices.forEach((choice) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.textContent = choice.label;
      if (choice.primary) {
        button.classList.add('primary');
      }

      button.addEventListener('click', () => {
        resolveDialog({
          value: choice.value,
          inputValue: elements.dialogInput.value,
        });
      });

      elements.dialogButtons.appendChild(button);
    });

    elements.dialogOverlay.classList.remove('is-hidden');

    return new Promise((resolve) => {
      state.dialogResolver = resolve;
      window.setTimeout(() => {
        if (input) {
          elements.dialogInput.focus();
        } else if (elements.dialogButtons.firstElementChild) {
          elements.dialogButtons.firstElementChild.focus();
        }
      }, 0);
    });
  }

  function resolveDialog(value) {
    if (!state.dialogResolver) {
      return;
    }

    const resolver = state.dialogResolver;
    state.dialogResolver = null;
    elements.dialogOverlay.classList.add('is-hidden');
    resolver(value);
  }

  function setAuthUiState() {
    if (state.isAuthenticated) {
      elements.uploadButton.disabled = false;
      elements.uploadButton.title = '';
      elements.logoutButton.textContent = 'Logout';
    } else {
      elements.uploadButton.disabled = true;
      elements.uploadButton.title = 'Accedi per caricare immagini';
      elements.logoutButton.textContent = 'Accedi';
      resetMoveState();
      stopMapPickMode();
    }
  }

  function openAuthOverlay() {
    elements.loginError.textContent = '';
    elements.authOverlay.classList.remove('is-hidden');
    window.setTimeout(() => {
      elements.usernameInput.focus();
    }, 0);
  }

  function closeAuthOverlay() {
    elements.authOverlay.classList.add('is-hidden');
  }

  function ensureAuthenticatedForEdit(actionLabel) {
    if (state.isAuthenticated) {
      return true;
    }

    setStatus(`Devi accedere per ${actionLabel}.`, 'error');
    openAuthOverlay();
    return false;
  }
})();
