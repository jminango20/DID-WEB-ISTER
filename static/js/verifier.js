/**
 * Verifier - client-side credential verification logic.
 */

async function runVerification() {
    const input = document.getElementById('credentialInput').value.trim();
    const resultsEl = document.getElementById('results');

    if (!input) {
        showError('Por favor, pega el JSON de la credencial antes de verificar.');
        return;
    }

    let credential;
    try {
        credential = JSON.parse(input);
    } catch (e) {
        showError('JSON inválido: ' + e.message);
        return;
    }

    resultsEl.style.display = 'block';
    resultsEl.innerHTML = '<p style="text-align:center;color:#667eea;padding:24px;">Verificando...</p>';

    try {
        const response = await fetch('/verify/check', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ credential })
        });

        const result = await response.json();

        if (!response.ok || result.error) {
            showError(result.error || 'Error en la verificación.');
            return;
        }

        displayResults(result);

    } catch (error) {
        showError('Error de conexión: ' + error.message);
    }
}

function displayResults(result) {
    const resultsEl = document.getElementById('results');
    const statusClass = result.valid ? 'valid' : 'invalid';
    const statusIcon = result.valid ? '✓' : '✗';
    const cred = result.credential || {};
    const subject = cred.credentialSubject || {};
    const hasCred = subject.hasCredential || {};

    const issuanceDateFormatted = cred.issuanceDate
        ? new Date(cred.issuanceDate).toLocaleDateString('es-EC', { year: 'numeric', month: 'long', day: 'numeric' })
        : '-';

    resultsEl.innerHTML = `
        <div class="status-banner ${statusClass}">
            <h2>${statusIcon} ${result.message}</h2>
            <p>${result.valid
                ? 'La firma digital es válida. Esta credencial fue emitida por el Instituto ISTER.'
                : 'La firma digital no es válida. Esta credencial puede haber sido alterada.'
            }</p>
        </div>

        <div class="detail-card">
            <h3>Información del Estudiante</h3>
            <div class="detail-row">
                <span class="detail-label">Nombre</span>
                <span class="detail-value">${subject.name || '-'}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">ID Estudiante</span>
                <span class="detail-value">${subject.studentId || '-'}</span>
            </div>
        </div>

        <div class="detail-card">
            <h3>Información del Curso</h3>
            <div class="detail-row">
                <span class="detail-label">Curso</span>
                <span class="detail-value">${hasCred.courseName || '-'}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Fecha de finalización</span>
                <span class="detail-value">${hasCred.completionDate || '-'}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Calificación</span>
                <span class="detail-value">${hasCred.grade || '-'}</span>
            </div>
        </div>

        <div class="detail-card">
            <h3>Información de la Credencial</h3>
            <div class="detail-row">
                <span class="detail-label">Emisor</span>
                <span class="detail-value">${cred.issuer || '-'}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Fecha de emisión</span>
                <span class="detail-value">${issuanceDateFormatted}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">ID de credencial</span>
                <span class="detail-value">${cred.id || '-'}</span>
            </div>
        </div>

        <div class="result-actions">
            <button class="btn-secondary" onclick="resetVerifier()">Verificar otra credencial</button>
        </div>
    `;
}

function showError(message) {
    const resultsEl = document.getElementById('results');
    resultsEl.style.display = 'block';
    resultsEl.innerHTML = `
        <div class="status-banner error">
            <h2>⚠ Error</h2>
            <p>${message}</p>
        </div>
        <div class="result-actions">
            <button class="btn-secondary" onclick="resetVerifier()">Intentar de nuevo</button>
        </div>
    `;
}

function resetVerifier() {
    document.getElementById('credentialInput').value = '';
    document.getElementById('results').style.display = 'none';
    document.getElementById('results').innerHTML = '';
}
