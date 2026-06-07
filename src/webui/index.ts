import { Router, RequestHandler, Request } from 'express';
import { existsSync, readFileSync } from 'fs';
import session from 'express-session';
import cookies from 'cookie-parser';
import createMemoryStore from 'memorystore';
import flash from 'connect-flash';
import { VERSION } from '../utils/Consts';
import {
  CONFIG_MAP,
  CONFIG_DATA,
  CONFIG,
  CONFIG_OPTIONS,
  SaveConfig,
  ARGS,
  DATAFILE_MAP,
  FILE_CHECK,
} from '../utils/ArgConfig';
import { get, isEmpty } from 'lodash';
import { Converter } from 'showdown';
import {
    ReadAssets,
    PLUGIN_PATH,
    GetProfileCount,
    GetProfiles,
    FindCardsByRefid,
    Count,
    FindProfile,
    FindProfileByUsername,
    PurgeProfile,
    UpdateProfile,
    CreateCard,
    FindCard,
    DeleteCard,
    APIFind,
    APIRemove,
    PluginStats,
    PurgePlugin,
    APIFindOne,
    APIInsert,
    APIUpdate,
    APIUpsert,
    APICount,
    CreateProfile,
} from '../utils/EamuseIO';
import { urlencoded, json } from 'body-parser';
import path from 'path';
import { ROOT_CONTAINER } from '../eamuse/index';
import { fun } from './fun';
import { card2nfc, nfc2card, cardType } from '../utils/CardCipher';
import { groupBy, startCase, lowerCase, upperFirst } from 'lodash';
import { sizeof } from 'sizeof';
import { ajax as emit } from './emit';
import { Logger } from '../utils/Logger';
import { hashPassword, isBcryptHash, verifyPassword, type WebProfile } from '../utils/Auth';

const memorystore = createMemoryStore(session);

export const webui = Router();
webui.use(
  session({
    cookie: { maxAge: 300000, sameSite: true },
    secret: 'c0dedeadc0debeef',
    resave: true,
    saveUninitialized: false,
    store: new memorystore({ checkPeriod: 300000 }),
  })
);
webui.use(cookies());

webui.use(flash());
let wrap = (fn: RequestHandler) => (...args: any[]) => (fn as any)(...args).catch(args[2]);

function normalizeUsername(value: any): string{
    return typeof value == 'string' ? value.trim() : '';
}

function getSessionProfile(req: Request): WebProfile{
    return (req as any).session?.webui_user || {username: 'Unauthorized', refId: '', admin: false};
}

function hasProfileAccess(req: Request, profileOrRefId: string | WebProfile): boolean {
    const webProfile = getSessionProfile(req);
    if (webProfile.admin) return true;
    if(typeof profileOrRefId == 'string'){
        return webProfile.refId === profileOrRefId;
    }
    return !!profileOrRefId.public || webProfile.refId === profileOrRefId.refId;
}

function isSecureWebUIRequest(req: Request): boolean {
    if (req.secure) return true;

    const forwardedProto = req.headers['x-forwarded-proto'];
    if (typeof forwardedProto == 'string') {
        return forwardedProto.split(',')[0].trim().toLowerCase() == 'https';
    }

    return false;
}

function normalizeCardInput(raw: string): { cid: string; print: string } | null {
    if(raw.length === 0){
        return null;
    }

    try{
        const cid = raw.toUpperCase();
        const print = nfc2card(cid);
        if(cardType(cid) >= 0){
            return { cid, print };
        }
    }catch{
    }

    try{
        const print = raw
            .toUpperCase()
            .trim()
            .replace(/[\s\-]/g, '')
            .replace(/O/g, '0')
            .replace(/I/g, '1');
        const cid = card2nfc(print);
        if(cardType(cid) >= 0){
            return { cid, print };
        }
    }catch{}
    return null;
}

webui.use(
    wrap(async (req, res, next) => {
        if (!CONFIG.webui_require_https || isSecureWebUIRequest(req)) {
            return next();
        }

        res.status(403).render('https_required', data(req, 'HTTPS 필요', 'core', {
            requestedUrl: req.originalUrl || '/',
        }));
    })
);

webui.get(
  '/login',
  wrap(async (req, res) => {
    const nextUrl =
      typeof req.query.next == 'string' && req.query.next.startsWith('/') ? req.query.next : '/';
    res.render('login', data(req, 'Login', 'core', { next: nextUrl }));
  })
);

webui.post(
    '/login',
    urlencoded({ extended: true, limit: '1kb' }),
    wrap(async (req, res) => {
        const username = normalizeUsername(req.body?.username);
        const password = (req.body?.password ?? '').toString();
        if(username.length > 0){
            const profile = await FindProfileByUsername(username);
            if(profile && typeof profile.password === 'string'){
                if(await verifyPassword(password, profile.password)){
                    (req as any).session.webui_authed = true;
                    let webProfile: WebProfile = {
                        username,
                        refId: profile.__refid,
                        admin: !!profile.admin,
                        public: !!profile.public,
                    };
                    (req as any).session.webui_user = webProfile;
                    if(!webProfile.admin && !isBcryptHash(profile.password)){
                        const hashed = await hashPassword(password);
                        await UpdateProfile(profile.__refid, { password: hashed });
                    }
                    const nextUrl =
                        typeof req.body.next == 'string' && req.body.next.startsWith('/')
                            ? req.body.next : '/';
                    return res.redirect(nextUrl);
                }
            }
        }
        req.flash('formWarn', 'Invalid username or password');
        res.redirect('/login');
    }),
);

webui.get(
    '/register',
    wrap(async (req, res) => {
        const nextUrl =
            typeof req.query.next == 'string' && req.query.next.startsWith('/') ? req.query.next : '/';
        res.render('register', data(req, 'Register', 'core', { next: nextUrl }));
    })
);

webui.post(
    '/register',
    urlencoded({ extended: true, limit: '1kb' }),
    wrap(async (req, res) => {
        const nextUrl =
            typeof req.body.next == 'string' && req.body.next.startsWith('/') ? req.body.next : '/';

        const username = normalizeUsername(req.body?.username);
        const password = (req.body?.password ?? '').toString();
        const confirmPassword = (req.body?.confirmPassword ?? '').toString();
        const cardInput = req.body?.cardNumber;

        if (username.length < 1) {
            req.flash('formWarn', 'Username is required');
            return res.redirect('/login');
        }
        if (password.length < 4) {
            req.flash('formWarn', 'Password must be at least 4 characters');
            return res.redirect('/login');
        }
        if (password !== confirmPassword) {
            req.flash('formWarn', 'Password confirmation does not match');
            return res.redirect('/login');
        }

        const existingByUsername = await FindProfileByUsername(username);
        const cardInfo = normalizeCardInput(cardInput);

        if (cardInput && typeof cardInput == 'string' && cardInput.trim().length > 0 && !cardInfo) {
            req.flash('formWarn', 'Invalid card number format');
            return res.redirect('/login');
        }

        const hashed = await hashPassword(password);

        // 카드가 있으면 기존 카드 소유 프로필 우선
        if (cardInfo) {
            const existingCard = await FindCard(cardInfo.cid);
            if (existingCard && typeof existingCard.__refid === 'string') {
                const refId = existingCard.__refid;
                if (existingByUsername && existingByUsername.__refid !== refId) {
                    req.flash('formWarn', 'Username already exists');
                    return res.redirect('/login');
                }

                const owner = await FindProfile(refId);
                if (!owner) {
                    req.flash('formWarn', 'Card owner profile not found');
                    return res.redirect('/login');
                }

                await UpdateProfile(refId, { username, password: hashed });

                (req as any).session.webui_authed = true;
                (req as any).session.webui_user = { username, refId, admin: false };
                req.flash('formOk', 'Registered and logged in');
                return res.redirect(nextUrl);
            }
        }

        // 새 프로필 생성
        if (existingByUsername) {
            req.flash('formWarn', 'Username already exists');
            return res.redirect('/login');
        }

        const created = await CreateProfile('0000');
        if (!created || typeof created.__refid !== 'string') {
            req.flash('formWarn', 'Failed to create profile');
            return res.redirect('/login');
        }

        const refId = created.__refid;
        await UpdateProfile(refId, { username, password: hashed });

        if (cardInfo) {
            await CreateCard(cardInfo.cid, refId, cardInfo.print);
        }

        (req as any).session.webui_authed = true;
        (req as any).session.webui_user = { username, refId, admin: created.admin };
        req.flash('formOk', 'Registered and logged in');
        return res.redirect(nextUrl);
    })
);

webui.get(
    '/logout',
    wrap(async (req, res) => {
        if((req as any).session){
            (req as any).session.webui_authed = false;
            (req as any).session.webui_user = null;
        }
        return res.redirect('/login');
    }),
);

webui.use(
  wrap(async (req, res, next) => {
    if (req.path == '/login' || req.path == '/logout' || req.path == '/register') {
      return next();
    }
    if ((req as any).session?.webui_authed) {
      return next();
    }

    const accept = req.headers['accept'] || '';
    const wantsHtml = typeof accept == 'string' && accept.includes('text/html');
    if (wantsHtml) {
      const nextUrl = encodeURIComponent(req.originalUrl || '/');
      return res.redirect(`/login?next=${nextUrl}`);
    }
    return res.status(401).json({ error: 'Unauthorized' });
  })
);

webui.use('/fun', fun);
webui.use('/', emit);

const markdown = new Converter({
  headerLevelStart: 3,
  strikethrough: true,
  tables: true,
  tasklists: true,
});

function data(req: Request, title: string, plugin: string, attr?: any) {
  const formOk = req.flash('formOk');
  const formWarn = req.flash('formWarn');
  const aside = req.cookies.asidemenu == 'true';

  let formMessage = null;
  if (formOk.length > 0) {
    formMessage = { danger: false, message: formOk.join(' ') };
  } else if (formWarn.length > 0) {
    formMessage = { danger: true, message: formWarn.join(' ') };
  }

  const webProfile = getSessionProfile(req);
  return {
    title,
    aside,
    plugin,
    admin: webProfile.admin,
    web_profile: webProfile,
    local: req.ip == '127.0.0.1' || req.ip == '::1',
    version: VERSION,
    formMessage,
    plugins: ROOT_CONTAINER.Plugins.map(p => {
      return {
        name: p.Name,
        id: p.Identifier,
        webOnly: p.GameCodes.length == 0,
        pages: p.Pages.map(f => ({ name: startCase(f), link: f })),
      };
    }),
    ...attr,
  };
}

function validate(c: CONFIG_OPTIONS, current: any) {
  if (c.validator) {
    const msg = c.validator(current);
    if (typeof msg == 'string') {
      return msg.length == 0 ? 'Invalid value' : msg;
    }
  }

  if (c.range) {
    if (c.type == 'float' || c.type == 'integer') {
      if (current < c.range[0] || current > c.range[1]) {
        return `Value must be in between ${c.range[0]} and ${c.range[1]}.`;
      }
    }
  }

  if (c.options) {
    if (c.type == 'string') {
      if (c.options.indexOf(current) < 0) {
        return `Please select an option.`;
      }
    }
  }

  return null;
}

function ConfigData(plugin: string) {
  const config: CONFIG_DATA[] = [];
  const configMap = CONFIG_MAP[plugin];
  const configData = plugin == 'core' ? CONFIG : CONFIG[plugin];

  if (!configMap || !configData) {
    return [];
  }

  if (configMap) {
    for (const [key, c] of configMap) {
      const name = get(c, 'name', upperFirst(lowerCase(key)));
      const current = get(configData, key, c.default);
      let error = validate(c, current);

      config.push({
        key,
        ...c,
        current,
        name,
        error,
      });
    }
  }
  return config;
}

function DataFileCheck(plugin: string) {
  const files: FILE_CHECK[] = [];
  const fileMap = DATAFILE_MAP[plugin];

  if (!fileMap) {
    return [];
  }

  for (const [filepath, c] of fileMap) {
    const target = path.resolve(PLUGIN_PATH, plugin, filepath);
    const filename = path.basename(target);
    const uploaded = existsSync(target);
    const config = { ...c };
    if (!c.name) {
      config.name = filename;
    }
    files.push({ ...config, path: filepath, uploaded, filename });
  }

  return files;
}

webui.get('/favicon.ico', async (req, res) => {
  res.redirect('/static/favicon.ico');
});

webui.get(
  '/',
  wrap(async (req, res) => {
    const memory = `${(process.memoryUsage().rss / 1048576).toFixed(2)}MB`;
    const config = ConfigData('core');

    const changelog = markdown.makeHtml(ReadAssets('changelog.md'));

    const profiles = await GetProfileCount();
    res.render('index', data(req, 'Dashboard', 'core', { memory, config, changelog, profiles }));
  })
);

webui.get(
  '/profiles',
  wrap(async (req, res) => {
    let profiles: any[] = [];
    const webProfile = getSessionProfile(req);
    if (webProfile.admin) {
      profiles = (await GetProfiles()) || [];
    } else {
      const refId = webProfile.refId;
      if (!refId) {
        return res.sendStatus(403);
      }
      const profile = await FindProfile(refId);
      profiles = profile ? [profile] : [];
    }
    for (const profile of profiles) {
      profile.cards = await Count({ __s: 'card', __refid: profile.__refid });
    }
    res.render('profiles', data(req, 'Profiles', 'core', { profiles }));
  })
);

webui.delete(
    '/profile/:refId',
    wrap(async (req, res) => {
        const refId = req.params['refId'];
        if(!hasProfileAccess(req, refId) || !(await PurgeProfile(refId))){
            return res.sendStatus(404);
        }
        return res.sendStatus(200);
    }),
);

webui.get(
  '/profile/:refId',
  wrap(async (req, res, next) => {
    const refId = req.params['refId'];
    if (!hasProfileAccess(req, refId)) {
      return res.sendStatus(403);
    }

    const profile = await FindProfile(refId);
    if (!profile) {
      return next();
    }

    profile.cards = await FindCardsByRefid(refId);

    res.render(
      'profiles_profile',
      data(req, 'Profiles', 'core', { profile, subtitle: profile.name })
    );
  })
);

webui.delete(
    '/card/:cid',
    wrap(async (req, res) => {
        const cid = req.params['cid'];
        const webProfile = getSessionProfile(req);
        if(!webProfile.admin){
            const card = await FindCard(cid);
            const refId = webProfile.refId;
            if(!card || !refId || card.__refid !== refId){
                return res.sendStatus(403);
            }
        }

        if(await DeleteCard(cid)){
            return res.sendStatus(200);
        }else{
            return res.sendStatus(404);
        }
    }),
);

webui.post(
  '/profile/:refId/card',
  json({ limit: '50mb' }),
  wrap(async (req, res) => {
    const refId = req.params['refId'];
    if (!hasProfileAccess(req, refId)) {
      return res.sendStatus(403);
    }
    const card = req.body.cid;

    try {
      const cid = card;
      const print = nfc2card(cid);

      if (!(await FindCard(cid))) {
        await CreateCard(cid, refId, print);
        return res.sendStatus(200);
      }
    } catch {}

    try {
      const print = card
        .toUpperCase()
        .trim()
        .replace(/[\s\-]/g, '')
        .replace(/O/g, '0')
        .replace(/I/g, '1');
      const cid = card2nfc(print);
      if (cardType(cid) >= 0 && !(await FindCard(cid))) {
        await CreateCard(cid, refId, print);
        return res.sendStatus(200);
      }
    } catch {}
    req.flash('formWarn', '카드 추가 실패');
    res.sendStatus(403);
  })
);

webui.post(
  '/profile/:refId',
  urlencoded({ extended: true, limit: '50mb' }),
  wrap(async (req, res) => {
    const refId = req.params['refId'];
    if (!hasProfileAccess(req, refId)) {
      return res.sendStatus(403);
    }
    const update: any = {};
    if (req.body.pin) {
      update.pin = req.body.pin;
    }
    if (req.body.name) {
      update.name = req.body.name;
    }
    if (req.body.username) {
      const nextUsername = req.body.username.toString().trim();
      if (nextUsername.length > 0) {
        const existing = await FindProfileByUsername(nextUsername);
        if (existing && existing.__refid !== refId) {
          req.flash('formWarn', 'Username already exists');
          return res.redirect(req.originalUrl);
        }
      }
      update.username = nextUsername;
    }
    if (req.body.password) {
      const nextPassword = req.body.password.toString();
      if (nextPassword.length > 0) {
        update.password = await hashPassword(nextPassword);
      }
    }

    await UpdateProfile(refId, update);
    req.flash('formOk', 'Updated');
    res.redirect(req.originalUrl);
  })
);

// Data Management
webui.get(
    '/data',
    wrap(async (req, res) => {
        if(!getSessionProfile(req).admin) return res.redirect('/');
        const pluginStats = await PluginStats();
        const installed = ROOT_CONTAINER.Plugins.map(p => p.Identifier);
        res.render(
            'data',
            data(req, '데이터 관리', 'core', { pluginStats, installed, dev: ARGS.dev }),
        );
    }),
);

webui.get(
  '/data/:plugin',
  wrap(async (req, res, next) => {
    if (!ARGS.dev) {
      next();
      return;
    }
    const pluginID = req.params['plugin'];

    res.render('data_plugin', data(req, 'Data Management', 'core', { subtitle: pluginID }));
  })
);

webui.post(
  '/data/db',
  json({ limit: '50mb' }),
  wrap(async (req, res, next) => {
    if (!ARGS.dev) {
      next();
      return;
    }
    const command = req.body.command;
    const args = req.body.args;
    const plugin = req.body.plugin;

    try {
      switch (command) {
        case 'FindOne':
          res.json(await (APIFindOne as any)({ identifier: plugin, core: false }, ...args));
          break;
        case 'Find':
          res.json(await (APIFind as any)({ identifier: plugin, core: false }, ...args));
          break;
        case 'Insert':
          res.json(await (APIInsert as any)({ identifier: plugin, core: false }, ...args));
          break;
        case 'Remove':
          res.json(await (APIRemove as any)({ identifier: plugin, core: false }, ...args));
          break;
        case 'Update':
          res.json(await (APIUpdate as any)({ identifier: plugin, core: false }, ...args));
          break;
        case 'Upsert':
          res.json(await (APIUpsert as any)({ identifier: plugin, core: false }, ...args));
          break;
        case 'Count':
          res.json(await (APICount as any)({ identifier: plugin, core: false }, ...args));
          break;
      }
    } catch (err) {
      res.json({ error: err.toString() });
    }
  })
);

webui.delete(
    '/data/:plugin',
    wrap(async (req, res) => {
        if(!getSessionProfile(req).admin) return res.sendStatus(404);
        const pluginID = req.params['plugin'];
        if(pluginID && pluginID.length > 0) await PurgePlugin(pluginID);

        const plugin = ROOT_CONTAINER.getPluginByID(pluginID);
        if(plugin){
            // Re-register for init data
            try{
                plugin.Register();
            }catch(err){
                Logger.error(err, { plugin: pluginID });
            }
        }
        res.sendStatus(200);
    }),
);

webui.get(
  '/about',
  wrap(async (req, res) => {
    const contributors = new Map<string, { name: string; link?: string }>();
    for (const plugin of ROOT_CONTAINER.Plugins) {
      for (const c of plugin.Contributors) {
        contributors.set(c.name, c);
      }
    }
    res.render(
      'about',
      data(req, 'About', 'core', { contributors: Array.from(contributors.values()) })
    );
  })
);

// Plugin Overview
webui.get(
  '/plugin/:plugin',
  wrap(async (req, res, next) => {
    const plugin = ROOT_CONTAINER.getPluginByID(req.params['plugin']);

    if (!plugin) {
      return next();
    }

    const readmePath = path.join(PLUGIN_PATH, plugin.Identifier, 'README.md');
    let readme = null;
    try {
      if (existsSync(readmePath)) {
        readme = markdown.makeHtml(readFileSync(readmePath, { encoding: 'utf-8' }));
      }
    } catch {
      readme = null;
    }

    const config = ConfigData(plugin.Identifier);
    const datafile = DataFileCheck(plugin.Identifier);
    const contributors = plugin ? plugin.Contributors : [];
    const gameCodes = plugin ? plugin.GameCodes : [];

    res.render(
      'plugin',
      data(req, plugin.Name, plugin.Identifier, {
        readme,
        config,
        datafile,
        contributors,
        gameCodes,
        subtitle: 'Overview',
        subidentifier: 'overview',
      })
    );
  })
);

webui.delete(
    '/plugin/:plugin/profile/:refId',
    wrap(async (req, res) => {
        if(!getSessionProfile(req).admin) return res.sendStatus(404);

        const plugin = ROOT_CONTAINER.getPluginByID(req.params['plugin']);
        if(!plugin){
            return res.sendStatus(404);
        }

        const refId = req.params['refId'];
        if(!refId || refId.length < 0){
            return res.sendStatus(400);
        }
        if(!hasProfileAccess(req, refId)){
            return res.sendStatus(403);
        }

        if(await APIRemove({ identifier: plugin.Identifier, core: true }, refId, {})){
            return res.sendStatus(200);
        }else{
            return res.sendStatus(404);
        }
    }),
);

// Plugin statics
webui.get(
  '/plugin/:plugin/static/*',
  wrap(async (req, res, next) => {
    const data = req.params[0];

    if (data.startsWith('.')) {
      return next();
    }

    const plugin = ROOT_CONTAINER.getPluginByID(req.params['plugin']);

    if (!plugin) {
      return next();
    }

    const file = path.join(PLUGIN_PATH, plugin.Identifier, 'webui', data);

    res.sendFile(file, {}, err => {
      if (err) {
        next();
      }
    });
  })
);

// Plugin Profiles
webui.get(
    '/plugin/:plugin/profiles',
    wrap(async (req, res, next) => {
        const plugin = ROOT_CONTAINER.getPluginByID(req.params['plugin']);
        if(!plugin){
            return next();
        }

        let profileDocs: any[] = [];
        const webProfile = getSessionProfile(req);
        if(webProfile.admin){
            profileDocs = await APIFind({ identifier: plugin.Identifier, core: true }, null, {});
        }else{
            const refId = webProfile.refId;
            if(!refId){
                return res.sendStatus(403);
            }
            profileDocs = await APIFind({ identifier: plugin.Identifier, core: true }, refId, {});
        }

        const profiles = groupBy(profileDocs, '__refid');

        const profileData: any[] = [];
        for(const refId in profiles){
            let name = undefined;
            for(const doc of profiles[refId]){
                if(doc.__refid == null){
                    PurgeProfile(doc.__refid);
                    break;
                }
                if(typeof doc.name == 'string'){
                    name = doc.name;
                    break;
                }
            }

            profileData.push({
                refid: refId,
                name,
                dataSize: sizeof(profiles[refId], true),
                coreProfile: await FindProfile(refId),
            });
        }

        res.render(
            'plugin_profiles',
            data(req, plugin.Name, plugin.Identifier, {
                subtitle: 'Profiles',
                subidentifier: 'profiles',
                hasCustomPage: plugin.FirstProfilePage != null,
                profiles: profileData,
            }),
        );
    }),
);

// Plugin Profile Page
webui.get(
  '/plugin/:plugin/profile',
  wrap(async (req, res, next) => {
    const plugin = ROOT_CONTAINER.getPluginByID(req.params['plugin']);

    if (!plugin) {
      return next();
    }

    const refId = req.query['refid'];

    if (refId == null) {
      return next();
    }
    if (!hasProfileAccess(req, refId.toString())) {
      return res.sendStatus(403);
    }

    const pageName = req.query['page'];
    const page = pageName == null ? plugin.FirstProfilePage : `profile_${pageName.toString()}`;

    const content = await plugin.render(page, { query: req.query }, refId.toString());
    if (content == null) {
      return next();
    }

    const tabs = plugin.ProfilePages.map(p => ({
      name: startCase(p.substr(8)),
      link: p.substr(8),
    }));

    res.render(
      'custom_profile',
      data(req, plugin.Name, plugin.Identifier, {
        content,
        tabs,
        subtitle: 'Profiles',
        subidentifier: 'profiles',
        subsubtitle: startCase(page.substr(8)),
        subsubidentifier: page.substr(8),
        refid: refId.toString(),
      })
    );
  })
);

// Plugin Custom Pages
webui.get(
  '/plugin/:plugin/:page',
  wrap(async (req, res, next) => {
    const plugin = ROOT_CONTAINER.getPluginByID(req.params['plugin']);

    if (!plugin) {
      return next();
    }

    const pageName = req.params['page'];

    const content = await plugin.render(pageName, { query: req.query });
    if (content == null) {
      return next();
    }

    res.render(
      'custom',
      data(req, plugin.Name, plugin.Identifier, {
        content,
        subtitle: startCase(pageName),
        subidentifier: pageName,
      })
    );
  })
);

// General setting update
webui.post(
    '*',
    urlencoded({ extended: true, limit: '50mb' }),
    wrap(async (req, res) => {
        const page = (req.query as any).page;

        if(isEmpty(req.body)){
            res.sendStatus(400);
            return;
        }

        let plugin: string = null;
        if(req.path == '/'){
            plugin = 'core';
        }else if(req.path.startsWith('/plugin/')){
            plugin = path.basename(req.path);
        }

        if(plugin == null){
            res.redirect(req.originalUrl);
            return;
        }

        if(page || !getSessionProfile(req).admin){
            // Custom page form or not admin
        }else{
            const configMap = CONFIG_MAP[plugin];
            const configData = plugin == 'core' ? CONFIG : CONFIG[plugin];

            if(configMap == null || configData == null){
                res.redirect(req.originalUrl);
                return;
            }

            let errorMessage = '';
            let needRestart = false;
            for(const [key, config] of configMap){
                let newValue = req.body[key];

                const beforeValue = configData[key];
                if(config.type === 'boolean'){
                    configData[key] = newValue != null;
                }else if(config.type === 'float'){
                    if(newValue == null) continue;
                    newValue = parseFloat(newValue);
                    if(!Number.isFinite(newValue)){
                        errorMessage = `'${key}' 옵션은 실수만 입력 가능합니다.`;
                        break;
                    }
                    configData[key] = newValue;
                }else if(config.type === 'integer'){
                    if(newValue == null) continue;
                    newValue = parseInt(newValue);
                    if(!Number.isFinite(newValue)){
                        errorMessage = `'${key}' 옵션은 정수만 입력 가능합니다.`;
                        break;
                    }
                    configData[key] = newValue;
                }else if(config.type === 'string'){
                    if(newValue == null) continue;
                    configData[key] = newValue;
                }else if(config.type === 'password'){
                    if(newValue == null) continue;
                    if(newValue.length > 3){
                        configData[key] = await hashPassword(newValue);
                    }else{
                        errorMessage = `비밀번호는 최소 4자 이상이어야 합니다.`;
                        break;
                    }
                }

                if(beforeValue !== configData[key]){
                    if(!validate(config, configData[key])){
                        if(config.needRestart){
                            needRestart = true;
                        }
                    }
                }
            }

            if(errorMessage){
                req.flash('formWarn', errorMessage);
            }else{
                if(needRestart){
                    req.flash('formWarn', '수정된 항목중 일부는 재시작해야 적용됩니다.');
                }else{
                    req.flash('formOk', '변경 완료');
                }
                SaveConfig();
            }
        }
        res.redirect(req.originalUrl);
    }),
);

// 404
webui.use(async (req, res, next) => {
  return res.status(404).render('404', data(req, '404 - Are you lost?', 'core'));
});

// 500 - Any server error
webui.use((err: any, req: any, res: any, next: any) => {
  return res.status(500).render('500', data(req, '500 - Oops', 'core', { err }));
});
