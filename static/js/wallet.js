/**
 * Wallet - gestión de credenciales en localStorage.
 *
 * Clave de almacenamiento: 'ister_credentials' -> array de objetos credential (W3C VC)
 */

const STORAGE_KEY = 'ister_credentials';

// ── Funciones de almacenamiento ──────────────────────────────────────────────

function getCredentials() {
    try {
        return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
    } catch {
        return [];
    }
}

function saveCredential(credential) {
    const credentials = getCredentials();
    // Evitar duplicados por ID
    const exists = credentials.some(c => c.id === credential.id);
    if (!exists) {
        credentials.push(credential);
        localStorage.setItem(STORAGE_KEY, JSON.stringify(credentials));
    }
    return !exists;
}

function deleteCredential(credentialId) {
    const credentials = getCredentials().filter(c => c.id !== credentialId);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(credentials));
}

function getCredentialById(credentialId) {
    return getCredentials().find(c => c.id === credentialId) || null;
}

// ── Página: index.html ───────────────────────────────────────────────────────

function renderWalletHome() {
    const listEl = document.getElementById('credential-list');
    const emptyEl = document.getElementById('empty-state');
    if (!listEl) return;

    const credentials = getCredentials();

    if (credentials.length === 0) {
        if (emptyEl) emptyEl.style.display = 'block';
        listEl.style.display = 'none';
        return;
    }

    if (emptyEl) emptyEl.style.display = 'none';
    listEl.style.display = 'block';
    listEl.innerHTML = '';

    credentials.forEach(cred => {
        const subject = cred.credentialSubject || {};
        const course = subject.hasCredential || {};
        const card = document.createElement('div');
        card.className = 'credential-card';
        card.innerHTML = `
            <div class="credential-header">
                <span class="credential-icon">🎓</span>
                <div>
                    <h3>${course.courseName || 'Credencial'}</h3>
                    <p class="credential-meta">${subject.name || ''}</p>
                </div>
            </div>
            <div class="credential-details">
                <span>📅 ${course.completionDate || ''}</span>
                ${course.grade ? `<span>⭐ Calificación: ${course.grade}</span>` : ''}
            </div>
            <div class="credential-actions">
                <button class="btn-view" onclick="viewCredential('${encodeURIComponent(cred.id)}')">
                    Ver detalle
                </button>
                <button class="btn-delete" onclick="confirmDelete('${encodeURIComponent(cred.id)}')">
                    Eliminar
                </button>
            </div>
        `;
        listEl.appendChild(card);
    });
}

function viewCredential(encodedId) {
    const id = decodeURIComponent(encodedId);
    window.location.href = `/wallet/view?id=${encodeURIComponent(id)}`;
}

function confirmDelete(encodedId) {
    if (confirm('¿Eliminar esta credencial de tu wallet? Esta acción no se puede deshacer.')) {
        deleteCredential(decodeURIComponent(encodedId));
        renderWalletHome();
    }
}

// ── Página: claim.html ───────────────────────────────────────────────────────

async function loadClaimPage(claimId) {
    const statusEl = document.getElementById('status');
    const contentEl = document.getElementById('credential-content');
    const saveBtn = document.getElementById('save-btn');

    if (!statusEl) return;

    try {
        statusEl.textContent = 'Cargando credencial...';

        const response = await fetch(`/api/credentials/${claimId}`);
        const result = await response.json();

        if (!response.ok) {
            statusEl.textContent = result.error || 'Credencial no encontrada.';
            return;
        }

        const credential = result.data;
        const subject = credential.credentialSubject || {};
        const course = subject.hasCredential || {};

        statusEl.style.display = 'none';
        contentEl.style.display = 'block';

        document.getElementById('c-name').textContent = subject.name || '-';
        document.getElementById('c-course').textContent = course.courseName || '-';
        document.getElementById('c-date').textContent = course.completionDate || '-';
        document.getElementById('c-grade').textContent = course.grade || '-';
        document.getElementById('c-issuer').textContent = credential.issuer || '-';
        document.getElementById('c-issued').textContent =
            new Date(credential.issuanceDate).toLocaleDateString('es-EC');

        // Verificar si ya está guardada
        if (getCredentialById(credential.id)) {
            saveBtn.textContent = '✓ Ya guardada en tu wallet';
            saveBtn.disabled = true;
        }

        saveBtn.addEventListener('click', async () => {
            const saved = saveCredential(credential);

            // Marcar como reclamada en el servidor
            await fetch(`/api/credentials/${claimId}/claim`, { method: 'POST' });

            if (saved) {
                saveBtn.textContent = '✓ Guardada en tu wallet';
                saveBtn.disabled = true;
                saveBtn.className = 'btn-saved';
            }
        });

    } catch (error) {
        statusEl.textContent = 'Error al cargar la credencial: ' + error.message;
    }
}

// ── Página: view_credential.html ─────────────────────────────────────────────

function loadViewPage() {
    const params = new URLSearchParams(window.location.search);
    const credentialId = params.get('id');

    if (!credentialId) {
        window.location.href = '/wallet/';
        return;
    }

    const credential = getCredentialById(credentialId);

    if (!credential) {
        window.location.href = '/wallet/';
        return;
    }

    const subject = credential.credentialSubject || {};
    const course = subject.hasCredential || {};

    document.getElementById('v-name').textContent = subject.name || '-';
    document.getElementById('v-student-id').textContent = subject.studentId || '-';
    document.getElementById('v-course').textContent = course.courseName || '-';
    document.getElementById('v-date').textContent = course.completionDate || '-';
    document.getElementById('v-grade').textContent = course.grade || '-';
    document.getElementById('v-issuer').textContent = credential.issuer || '-';
    document.getElementById('v-issued').textContent =
        new Date(credential.issuanceDate).toLocaleDateString('es-EC');
    document.getElementById('v-id').textContent = credential.id || '-';

    // Mostrar JSON completo
    const jsonEl = document.getElementById('v-json');
    if (jsonEl) {
        jsonEl.textContent = JSON.stringify(credential, null, 2);
    }

    // Botón copiar JSON
    const copyBtn = document.getElementById('copy-btn');
    if (copyBtn) {
        copyBtn.addEventListener('click', () => {
            navigator.clipboard.writeText(JSON.stringify(credential, null, 2));
            copyBtn.textContent = '✓ Copiado';
            setTimeout(() => { copyBtn.textContent = 'Copiar JSON'; }, 2000);
        });
    }
}

// ── Página: recover.html ─────────────────────────────────────────────────────

async function recoverCredentials() {
    const emailEl = document.getElementById('email');
    const statusEl = document.getElementById('recover-status');
    const email = emailEl ? emailEl.value.trim() : '';

    if (statusEl) statusEl.style.display = 'block';

    if (!email) {
        if (statusEl) statusEl.textContent = 'Ingresa tu correo electrónico.';
        return;
    }

    if (statusEl) statusEl.textContent = 'Buscando credenciales...';

    try {
        const response = await fetch('/api/recover', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });
        const result = await response.json();
        const credentials = result.data?.credentials || [];

        if (credentials.length === 0) {
            if (statusEl) statusEl.textContent = 'No se encontraron credenciales para ese correo.';
            return;
        }

        let saved = 0;
        for (const cred of credentials) {
            if (saveCredential(cred)) {
                saved++;
                // Extraer claim_id del ID de la credencial y marcarla como reclamada
                // Formato: did:web:.../credentials/CLAIM_ID
                const parts = (cred.id || '').split('/credentials/');
                if (parts.length === 2) {
                    await fetch(`/api/credentials/${parts[1]}/claim`, { method: 'POST' });
                }
            }
        }

        if (statusEl) {
            statusEl.textContent = saved > 0
                ? `✓ ${saved} credencial(es) recuperada(s) y guardada(s) en tu wallet.`
                : 'Las credenciales ya estaban en tu wallet.';
        }
    } catch (error) {
        if (statusEl) statusEl.textContent = 'Error: ' + error.message;
    }
}
