import { LitElement, html, css } from 'lit';
import { JsonRpc } from 'jsonrpc';
import '@vaadin/text-field';
import '@vaadin/text-area';
import '@vaadin/button';

/**
 * Shows the verification policy in effect and verifies a pasted raw request, printing its signature base.
 */
export class QwcHttpSignaturesVerify extends LitElement {
    jsonRpc = new JsonRpc(this);

    static styles = css`
        :host { display: flex; flex-direction: column; gap: 1rem; padding: 1rem; }
        vaadin-text-area { width: 100%; min-height: 12rem; font-family: monospace; }
        pre { background: var(--lumo-contrast-5pct); padding: 0.75rem; overflow: auto; white-space: pre-wrap; }
        .ok { color: var(--lumo-success-text-color); }
        .bad { color: var(--lumo-error-text-color); }
    `;

    static properties = {
        _policy: { state: true },
        _raw: { state: true },
        _base: { state: true },
        _result: { state: true },
    };

    constructor() {
        super();
        this._policy = null;
        this._raw = 'POST /inbox HTTP/1.1\nHost: example.com\nDate: \nContent-Type: application/json\nSignature: \n\n{}';
        this._base = 'https://example.com';
        this._result = null;
    }

    connectedCallback() {
        super.connectedCallback();
        this.jsonRpc.policy().then(r => { this._policy = r.result; });
    }

    render() {
        return html`
            ${this._policy ? html`<div><strong>Policy</strong><pre>${JSON.stringify(this._policy, null, 2)}</pre></div>` : ''}
            <vaadin-text-field label="Base URL" .value=${this._base} @value-changed=${e => { this._base = e.detail.value; }}></vaadin-text-field>
            <vaadin-text-area label="Raw request" .value=${this._raw} @value-changed=${e => { this._raw = e.detail.value; }}></vaadin-text-area>
            <vaadin-button theme="primary" @click=${this._verify}>Verify</vaadin-button>
            ${this._result ? html`
                <div class=${this._result.ok ? 'ok' : 'bad'}><strong>${this._result.ok ? 'Valid' : 'Rejected: ' + this._result.reason}</strong> ${this._result.message || ''}</div>
                ${this._result.signatureBase ? html`<div><strong>Signature base</strong><pre>${this._result.signatureBase}</pre></div>` : ''}
                <pre>${JSON.stringify(this._result, null, 2)}</pre>` : ''}
        `;
    }

    _verify() {
        this.jsonRpc.verify({ rawRequest: this._raw, baseUrl: this._base }).then(r => { this._result = r.result; });
    }
}
customElements.define('qwc-http-signatures-verify', QwcHttpSignaturesVerify);
