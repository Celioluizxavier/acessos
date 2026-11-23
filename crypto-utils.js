/* =====================================================================
 * crypto-utils.js
 * Funções reutilizáveis de criptografia (somente Web Crypto API).
 *  - Assinatura digital: Ed25519 (preferencial) ou ES256 (ECDSA P-256)
 *  - Hash de senha: PBKDF2-SHA256 com 210.000 iterações + salt
 *  - Utilitários: Base64, comparação em tempo constante, JSON canônico
 * Nenhuma dependência externa. Sem eval. Sem innerHTML.
 * ===================================================================== */
(function (raiz) {
  'use strict';

  const ITERACOES_PBKDF2 = 210000;
  const codificador = new TextEncoder();

  // Configuração dos algoritmos suportados.
  // ES256 é o plano B caso o navegador não suporte Ed25519 na Web Crypto API.
  const ALGORITMOS = {
    'Ed25519': {
      gerar: { name: 'Ed25519' },
      importar: { name: 'Ed25519' },
      assinar: { name: 'Ed25519' }
    },
    'ES256': {
      gerar: { name: 'ECDSA', namedCurve: 'P-256' },
      importar: { name: 'ECDSA', namedCurve: 'P-256' },
      assinar: { name: 'ECDSA', hash: 'SHA-256' }
    }
  };

  function sub() {
    if (!raiz.crypto || !raiz.crypto.subtle) {
      throw new Error('Web Crypto indisponível. Abra a página via HTTPS ou localhost.');
    }
    return raiz.crypto.subtle;
  }

  function cfg(alg) {
    const c = ALGORITMOS[alg];
    if (!c) throw new Error('Algoritmo não suportado: ' + alg);
    return c;
  }

  // ---------- Base64 / bytes ----------
  function bytesParaB64(dados) {
    const bytes = dados instanceof Uint8Array ? dados : new Uint8Array(dados);
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  function b64ParaBytes(b64) {
    const s = atob(b64);
    const bytes = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
    return bytes;
  }

  function base64Valido(texto) {
    return typeof texto === 'string' && texto.length > 0 &&
      texto.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(texto);
  }

  // ---------- Comparação em tempo constante ----------
  function comparacaoConstante(a, b) {
    a = String(a); b = String(b);
    const tamanho = Math.max(a.length, b.length);
    let diff = a.length ^ b.length;
    for (let i = 0; i < tamanho; i++) {
      diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
    }
    return diff === 0;
  }

  // ---------- JSON canônico (chaves ordenadas) ----------
  // Garante que admin e cliente assinem/verifiquem exatamente o mesmo texto,
  // independentemente da ordem dos campos ou da formatação do arquivo.
  function stringifyCanonico(v) {
    if (v === null || typeof v !== 'object') return JSON.stringify(v);
    if (Array.isArray(v)) return '[' + v.map(stringifyCanonico).join(',') + ']';
    return '{' + Object.keys(v).sort()
      .map(k => JSON.stringify(k) + ':' + stringifyCanonico(v[k])).join(',') + '}';
  }

  // O que é assinado: TODOS os campos exceto "assinatura".
  function payloadParaAssinar(doc) {
    const copia = {};
    Object.keys(doc).forEach(k => { if (k !== 'assinatura') copia[k] = doc[k]; });
    return stringifyCanonico(copia);
  }

  // ---------- Senha: PBKDF2 ----------
  function gerarSaltB64(tamanho) {
    const salt = new Uint8Array(tamanho || 16);
    raiz.crypto.getRandomValues(salt);
    return bytesParaB64(salt);
  }

  async function hashSenha(senha, saltBytes) {
    const base = await sub().importKey('raw', codificador.encode(senha), 'PBKDF2', false, ['deriveBits']);
    const bits = await sub().deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations: ITERACOES_PBKDF2 },
      base, 256);
    return bytesParaB64(bits);
  }

  async function sha256B64(texto) {
    return bytesParaB64(await sub().digest('SHA-256', codificador.encode(texto)));
  }

  // ---------- Assinatura digital ----------
  async function ed25519Suportado() {
    try {
      await sub().generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
      return true;
    } catch (e) { return false; }
  }

  async function gerarParDeChaves(alg) {
    const par = await sub().generateKey(cfg(alg).gerar, true, ['sign', 'verify']);
    const priv = await sub().exportKey('pkcs8', par.privateKey);
    const pub = await sub().exportKey('spki', par.publicKey);
    return { alg: alg, privadaB64: bytesParaB64(priv), publicaB64: bytesParaB64(pub) };
  }

  // Deriva a chave pública a partir da privada (via JWK).
  async function derivarChavePublica(alg, privadaB64) {
    const c = cfg(alg);
    const priv = await sub().importKey('pkcs8', b64ParaBytes(privadaB64), c.importar, true, ['sign']);
    const jwk = await sub().exportKey('jwk', priv);
    delete jwk.d; delete jwk.key_ops; delete jwk.alg; delete jwk.ext;
    const pub = await sub().importKey('jwk', jwk, c.importar, true, ['verify']);
    return bytesParaB64(await sub().exportKey('spki', pub));
  }

  async function assinar(alg, privadaB64, texto) {
    const c = cfg(alg);
    const chave = await sub().importKey('pkcs8', b64ParaBytes(privadaB64), c.importar, false, ['sign']);
    const sig = await sub().sign(c.assinar, chave, codificador.encode(texto));
    return bytesParaB64(sig);
  }

  // Retorna true/false (nunca lança por assinatura inválida).
  async function verificar(alg, publicaB64, texto, assinaturaB64) {
    try {
      const c = cfg(alg);
      const chave = await sub().importKey('spki', b64ParaBytes(publicaB64), c.importar, false, ['verify']);
      return await sub().verify(c.assinar, chave, b64ParaBytes(assinaturaB64), codificador.encode(texto));
    } catch (e) {
      return false;
    }
  }

  const API = {
    ITERACOES_PBKDF2, ALGORITMOS,
    bytesParaB64, b64ParaBytes, base64Valido, comparacaoConstante,
    stringifyCanonico, payloadParaAssinar,
    gerarSaltB64, hashSenha, sha256B64,
    ed25519Suportado, gerarParDeChaves, derivarChavePublica, assinar, verificar
  };

  raiz.CryptoUtils = API;
  if (typeof module !== 'undefined' && module.exports) module.exports = API;
})(typeof globalThis !== 'undefined' ? globalThis : window);
