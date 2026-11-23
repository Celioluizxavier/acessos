/* =====================================================================
 * auth.js  —  Módulo de autenticação (cliente)
 *
 * Fluxo do login:
 *   1) limite de tentativas  2) baixa o JSON de autorização
 *   3) hora confiável online 4) verifica assinatura + anti-replay
 *   5) confere usuário/senha (PBKDF2) 6) confere vencimento
 *   7) cria sessão e (se faltam <= 10 dias) gera o aviso diário
 *
 * Requer crypto-utils.js carregado ANTES deste arquivo.
 * ===================================================================== */
(function (raiz) {
  'use strict';

  // =====================  CONFIGURAÇÃO (EDITE AQUI)  =====================
  const CONFIG = {
    // 1) URL pública dos arquivos de autorização (GitHub raw recomendado).
    //    Use {usuario} para ter UM ARQUIVO POR USUÁRIO (vários clientes):
    //    .../main/autorizacoes/{usuario}.json   → maria entra com maria.json, joao com joao.json
    //    Sem {usuario} a URL aponta para um arquivo único (um só usuário).
    URL_ARQUIVO: 'https://raw.githubusercontent.com/SEU_USUARIO/SEU_REPOSITORIO/main/autorizacoes/{usuario}.json',

    // 2) CHAVE PÚBLICA gerada no admin.html (é pública, pode ficar no código)
    CHAVE_PUBLICA: {
      alg: 'Ed25519',                 // ou 'ES256' (o admin.html informa qual usar)
      b64: 'COLE_AQUI_A_CHAVE_PUBLICA_EM_BASE64'
    },

    AO_SAIR: null,                    // (arquivo único) função chamada ao sair, em vez de redirecionar
    PAGINA_LOGIN: 'login.html',
    PAGINA_PROTEGIDA: 'index.html',

    DIAS_AVISO: 10,                   // avisa quando faltarem <= 10 dias
    TOLERANCIA_FUTURO_MS: 5 * 60 * 1000, // "gerado_em" no futuro: tolerância de 5 min
    SESSAO_HORAS: 8,                  // duração máxima da sessão

    MAX_TENTATIVAS: 5,                // por minuto
    BLOQUEIO_MIN: 15,                 // minutos de bloqueio

    TIMEOUT_REDE_MS: 10000,

    CHAVE_SESSAO: 'auth_sessao',
    CHAVE_LIMITE: 'auth_limite',
    CHAVE_AVISO: 'auth_ultimo_aviso',

    // Relógios online (tentados em ordem). Se todos falharem: Date.now() + aviso no console.
    FONTES_HORA: [
      {
        nome: 'timeapi.io',
        buscar: async function () {
          const r = await fetchComTimeout('https://timeapi.io/api/time/current/zone?timeZone=UTC', 6000);
          if (!r.ok) throw new Error('HTTP ' + r.status);
          const d = await r.json();
          // dateTime vem como "2026-11-23T13:00:00.1234567" (já em UTC)
          const ms = Date.parse(String(d.dateTime).slice(0, 19) + 'Z');
          if (isNaN(ms)) throw new Error('resposta inválida');
          return ms;
        }
      },
      {
        nome: 'worldtimeapi.org',
        buscar: async function () {
          const r = await fetchComTimeout('https://worldtimeapi.org/api/timezone/Etc/UTC', 6000);
          if (!r.ok) throw new Error('HTTP ' + r.status);
          const d = await r.json();
          const ms = Number(d.unixtime) * 1000;
          if (!isFinite(ms) || ms <= 0) throw new Error('resposta inválida');
          return ms;
        }
      }
    ]
  };
  // =======================================================================

  class ErroAuth extends Error {
    constructor(codigo, mensagem) { super(mensagem); this.codigo = codigo; }
  }

  const C = () => raiz.CryptoUtils;

  // ---------- utilidades ----------
  async function fetchComTimeout(url, ms, opcoes) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), ms);
    try {
      return await fetch(url, Object.assign({}, opcoes || {}, { signal: ctrl.signal }));
    } finally { clearTimeout(t); }
  }

  function formatarData(ms) {
    return new Date(ms).toLocaleDateString('pt-BR', { timeZone: 'America/Sao_Paulo' });
  }

  function diaSaoPaulo(ms) { // AAAA-MM-DD
    return new Date(ms).toLocaleDateString('en-CA', { timeZone: 'America/Sao_Paulo' });
  }

  // ---------- limite de tentativas (localStorage) ----------
  function lerLimite() {
    try {
      const o = JSON.parse(raiz.localStorage.getItem(CONFIG.CHAVE_LIMITE) || '{}');
      return {
        tentativas: Array.isArray(o.tentativas) ? o.tentativas.filter(n => typeof n === 'number') : [],
        bloqueadoAte: Number(o.bloqueadoAte) || 0
      };
    } catch (e) { return { tentativas: [], bloqueadoAte: 0 }; }
  }

  function salvarLimite(s) {
    try { raiz.localStorage.setItem(CONFIG.CHAVE_LIMITE, JSON.stringify(s)); } catch (e) { /* modo privado */ }
  }

  function registrarTentativa() {
    const agora = Date.now();
    const s = lerLimite();
    if (s.bloqueadoAte > agora) return { permitido: false, restanteMs: s.bloqueadoAte - agora };
    s.tentativas = s.tentativas.filter(t => agora - t < 60000);
    if (s.tentativas.length >= CONFIG.MAX_TENTATIVAS) {
      s.bloqueadoAte = agora + CONFIG.BLOQUEIO_MIN * 60000;
      s.tentativas = [];
      salvarLimite(s);
      return { permitido: false, restanteMs: CONFIG.BLOQUEIO_MIN * 60000 };
    }
    s.tentativas.push(agora);
    salvarLimite(s);
    return { permitido: true };
  }

  function limparTentativas() { salvarLimite({ tentativas: [], bloqueadoAte: 0 }); }

  // ---------- download do arquivo de autorização ----------
  async function baixarAutorizacao(usuario) {
    let url = CONFIG.URL_ARQUIVO;
    if (!url || url.indexOf('SEU_USUARIO') !== -1) {
      throw new ErroAuth('config', '⚙️ Configuração incompleta: defina URL_ARQUIVO no auth.js.');
    }
    if (url.indexOf('{usuario}') !== -1) {
      url = url.split('{usuario}').join(encodeURIComponent(usuario));
    }
    const sep = url.indexOf('?') === -1 ? '?' : '&';
    let resp;
    try {
      resp = await fetchComTimeout(url + sep + '_=' + Date.now(), CONFIG.TIMEOUT_REDE_MS, { cache: 'no-store' });
    } catch (e) {
      throw new ErroAuth('rede',
        '🌐 Não foi possível baixar o arquivo de autorização. Verifique sua internet. ' +
        'Se o problema persistir, a hospedagem pode estar bloqueando o acesso (CORS) ou a URL está incorreta.');
    }
    if (!resp.ok) {
      if (resp.status === 404 && CONFIG.URL_ARQUIVO.indexOf('{usuario}') !== -1) {
        // Usuário não cadastrado (ou removido): não revela se o usuário existe.
        throw new ErroAuth('inexistente', 'Usuário ou senha inválidos.');
      }
      throw new ErroAuth('http', '🌐 O servidor de autorização respondeu com erro ' + resp.status +
        '. Confira a URL e se o arquivo está público.');
    }
    const texto = await resp.text();
    if (/^\s*</.test(texto)) {
      throw new ErroAuth('formato', '📄 A URL retornou uma página web em vez do arquivo JSON. ' +
        'Use o link direto (raw) do arquivo.');
    }
    try { return JSON.parse(texto); } catch (e) {
      throw new ErroAuth('formato', '📄 O arquivo de autorização está corrompido (JSON inválido).');
    }
  }

  // ---------- hora confiável ----------
  async function obterHoraConfiavel() {
    for (const fonte of CONFIG.FONTES_HORA) {
      try {
        const ms = await fonte.buscar();
        return { ms: ms, fonte: fonte.nome, confiavel: true };
      } catch (e) {
        console.warn('[auth] Relógio online "' + fonte.nome + '" falhou:', e && e.message);
      }
    }
    console.warn('[auth] Nenhum relógio online respondeu. Usando Date.now() (relógio do computador, menos confiável).');
    return { ms: Date.now(), fonte: 'relogio-local', confiavel: false };
  }

  // ---------- validação do documento ----------
  async function validarDocumento(doc, agoraMs) {
    const textos = ['usuario', 'senha_hash', 'salt', 'vencimento', 'assinatura', 'gerado_em'];
    if (!doc || typeof doc !== 'object' || Array.isArray(doc) ||
        textos.some(k => typeof doc[k] !== 'string' || !doc[k])) {
      throw new ErroAuth('estrutura', '📄 O arquivo de autorização está incompleto ou em formato inválido.');
    }
    if (!C().base64Valido(doc.salt) || !C().base64Valido(doc.senha_hash) || !C().base64Valido(doc.assinatura)) {
      throw new ErroAuth('estrutura', '📄 O arquivo de autorização contém dados inválidos.');
    }
    const pk = CONFIG.CHAVE_PUBLICA;
    if (!pk || !pk.b64 || pk.b64.indexOf('COLE_AQUI') !== -1) {
      throw new ErroAuth('config', '⚙️ Configuração incompleta: defina CHAVE_PUBLICA no auth.js.');
    }
    const ok = await C().verificar(pk.alg, pk.b64, C().payloadParaAssinar(doc), doc.assinatura);
    if (!ok) {
      throw new ErroAuth('assinatura', '🔒 Assinatura do arquivo inválida. O arquivo foi alterado ou não foi gerado pelo administrador.');
    }
    const gerado = Date.parse(doc.gerado_em);
    const venc = Date.parse(doc.vencimento);
    if (isNaN(gerado) || isNaN(venc)) {
      throw new ErroAuth('estrutura', '📄 Datas inválidas no arquivo de autorização.');
    }
    if (gerado > agoraMs + CONFIG.TOLERANCIA_FUTURO_MS) {
      throw new ErroAuth('replay', '🔒 Arquivo rejeitado: data de geração no futuro. Verifique o relógio do administrador.');
    }
    return { vencimentoMs: venc };
  }

  // ---------- sessão ----------
  // Se o navegador bloquear o sessionStorage (ex.: página incorporada no Google Sites),
  // a sessão fica só na memória da aba (some ao recarregar).
  let sessaoMemoria = null;

  function salvarSessao(usuario, vencimentoMs) {
    const txt = JSON.stringify({
      usuario: usuario,
      vencimento: vencimentoMs,
      expiraEm: Date.now() + CONFIG.SESSAO_HORAS * 3600000
    });
    sessaoMemoria = txt;
    try { raiz.sessionStorage.setItem(CONFIG.CHAVE_SESSAO, txt); } catch (e) { /* usa memória */ }
  }

  function limparSessao() {
    sessaoMemoria = null;
    try { raiz.sessionStorage.removeItem(CONFIG.CHAVE_SESSAO); } catch (e) { /* ignora */ }
  }

  function lerSessaoBruta() {
    try { const v = raiz.sessionStorage.getItem(CONFIG.CHAVE_SESSAO); if (v) return v; } catch (e) { /* ignora */ }
    return sessaoMemoria;
  }

  function sessaoAtiva() {
    try {
      const s = JSON.parse(lerSessaoBruta() || 'null');
      if (!s || typeof s.vencimento !== 'number' || typeof s.expiraEm !== 'number') return null;
      const agora = Date.now();
      if (agora >= s.vencimento || agora >= s.expiraEm) {
        limparSessao();
        return null;
      }
      return s;
    } catch (e) { return null; }
  }

  // Chame no <head> da página protegida.
  function exigirLogin() {
    if (!sessaoAtiva()) {
      raiz.location.replace(CONFIG.PAGINA_LOGIN);
      return false;
    }
    const estilo = raiz.document && raiz.document.getElementById('auth-oculta');
    if (estilo) estilo.remove();
    return true;
  }

  function sair() {
    limparSessao();
    if (typeof CONFIG.AO_SAIR === 'function') { CONFIG.AO_SAIR(); return; }
    raiz.location.replace(CONFIG.PAGINA_LOGIN);
  }

  // ---------- login ----------
  async function login(usuario, senha) {
    usuario = String(usuario || '').trim().toLowerCase();
    senha = String(senha || '');
    if (!usuario || !senha) return { status: 'invalido', mensagem: 'Informe usuário e senha.' };
    if (!/^[a-z0-9._-]{1,64}$/.test(usuario)) {
      return { status: 'credenciais', mensagem: 'Usuário ou senha inválidos.' };
    }

    const lim = registrarTentativa();
    if (!lim.permitido) {
      const min = Math.ceil(lim.restanteMs / 60000);
      return { status: 'bloqueado', mensagem: '⛔ Muitas tentativas. Tente novamente em ' + min + ' minuto(s).' };
    }

    try {
      const [doc, hora] = await Promise.all([baixarAutorizacao(usuario), obterHoraConfiavel()]);
      const info = await validarDocumento(doc, hora.ms);

      // Calcula o hash SEMPRE (mesmo com usuário errado) para não revelar qual campo falhou.
      const hashDigitado = await C().hashSenha(senha, C().b64ParaBytes(doc.salt));
      const okUsuario = C().comparacaoConstante(usuario, doc.usuario);
      const okSenha = C().comparacaoConstante(hashDigitado, doc.senha_hash);
      if (!(okUsuario && okSenha)) {
        return { status: 'credenciais', mensagem: 'Usuário ou senha inválidos.' };
      }
      limparTentativas();

      if (hora.ms >= info.vencimentoMs) {
        return {
          status: 'expirado',
          mensagem: '⚠️ Pagamento pendente. Seu acesso expirou em ' + formatarData(info.vencimentoMs) +
            '. Entre em contato para renovar.'
        };
      }

      salvarSessao(doc.usuario, info.vencimentoMs);

      const dias = Math.ceil((info.vencimentoMs - hora.ms) / 86400000);
      let aviso = null;
      if (dias <= CONFIG.DIAS_AVISO) {
        const hoje = diaSaoPaulo(hora.ms);
        let ultimo = null;
        try { ultimo = raiz.localStorage.getItem(CONFIG.CHAVE_AVISO); } catch (e) { /* ignora */ }
        if (ultimo !== hoje) {
          aviso = '⏰ Atenção: seu acesso expira em ' + formatarData(info.vencimentoMs) +
            ' (faltam ' + dias + (dias === 1 ? ' dia' : ' dias') + ').';
          try { raiz.localStorage.setItem(CONFIG.CHAVE_AVISO, hoje); } catch (e) { /* ignora */ }
        }
      }
      return { status: 'ok', usuario: doc.usuario, diasRestantes: dias, aviso: aviso, horaFonte: hora.fonte };
    } catch (e) {
      if (e instanceof ErroAuth && e.codigo === 'inexistente') {
        return { status: 'credenciais', mensagem: e.message };
      }
      if (e instanceof ErroAuth) return { status: 'erro', codigo: e.codigo, mensagem: e.message };
      console.error('[auth] erro inesperado:', e);
      return { status: 'erro', codigo: 'inesperado', mensagem: '❌ Erro inesperado durante o login. Tente novamente.' };
    }
  }

  raiz.Auth = {
    CONFIG, ErroAuth,
    login, sessaoAtiva, exigirLogin, sair,
    // expostos para testes
    _baixarAutorizacao: baixarAutorizacao, _obterHoraConfiavel: obterHoraConfiavel,
    _validarDocumento: validarDocumento
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = raiz.Auth;
})(typeof globalThis !== 'undefined' ? globalThis : window);
