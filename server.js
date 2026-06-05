const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const session = require('express-session');

let sec;
try { sec = require('./security'); } catch(e) {
    sec = { securityHeaders:(q,r,n)=>n(), globalLimiter:(q,r,n)=>n(), authLimiter:(q,r,n)=>n(), sanitizeInput:(q,r,n)=>n(), bruteForceGuard:(q,r,n)=>n(), trackFail:()=>{}, resetFail:()=>{}, corsOptions:{origin:'*',methods:['GET','POST','PUT','DELETE'],allowedHeaders:['Content-Type','Authorization','X-Admin-Pass']} };
}

const app = express();
const PORT = process.env.PORT || 8080;
let ADMIN_PASS = process.env.ADMIN_PASS || 'admin123';

// OAuth Config - Set these in environment variables or here
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const FACEBOOK_APP_ID = process.env.FACEBOOK_APP_ID || '';
const FACEBOOK_APP_SECRET = process.env.FACEBOOK_APP_SECRET || '';
const BASE_URL = process.env.BASE_URL || 'http://localhost:' + PORT;
const SESSION_SECRET = process.env.SESSION_SECRET || 'velora-hub-secret-2024';

const DIRS = { uploads:path.join(__dirname,'uploads'), icons:path.join(__dirname,'uploads','icons'), apks:path.join(__dirname,'uploads','apks'), screenshots:path.join(__dirname,'uploads','screenshots'), data:path.join(__dirname,'data') };
Object.values(DIRS).forEach(d=>{if(!fs.existsSync(d))fs.mkdirSync(d,{recursive:true})});

const DATA_FILE=path.join(DIRS.data,'apps.json'), USERS_FILE=path.join(DIRS.data,'users.json'), SETTINGS_FILE=path.join(DIRS.data,'settings.json'), PRESETS_FILE=path.join(DIRS.data,'presets.json');

app.set('trust proxy',1);
app.use(sec.securityHeaders);
app.use(require('cors')(sec.corsOptions));
app.use(express.json({limit:'10mb'}));
app.use(sec.sanitizeInput);
app.use(sec.globalLimiter);
app.use(session({secret:SESSION_SECRET,resave:false,saveUninitialized:false,cookie:{maxAge:7*24*60*60*1000}}));
app.use(express.static(path.join(__dirname,'public')));
app.use('/uploads',express.static(DIRS.uploads));

const storage=multer.diskStorage({destination:function(req,file,cb){let d=DIRS.uploads;if(file.fieldname==='icon')d=DIRS.icons;else if(file.fieldname==='apk')d=DIRS.apks;else if(file.fieldname==='screenshots')d=DIRS.screenshots;cb(null,d)},filename:function(req,file,cb){cb(null,Date.now()+'-'+file.originalname.replace(/[^a-zA-Z0-9._-]/g,'_'))}});
const upload=multer({storage:storage,limits:{fileSize:500*1024*1024}});

function readJSON(file,def){if(!def)def=[];if(!fs.existsSync(file))fs.writeFileSync(file,JSON.stringify(def));try{return JSON.parse(fs.readFileSync(file,'utf8'))}catch(e){return def}}
function writeJSON(file,data){fs.writeFileSync(file,JSON.stringify(data,null,2))}

const defaultSettings={storeName:"VELORA HUB",logoUrl:"",primaryColor:"#3a7bd5",secondaryColor:"#e3f2fd",bgColor:"#f5f5f5",textColor:"#1f1f1f",fontFamily:"Inter",borderRadius:"12px",darkMode:false,customCSS:"",announcementText:"",announcementBgColor:"#3a7bd5",announcementTextColor:"#ffffff",announcementLink:"",bannerTitle:"Welcome to VELORA HUB",bannerSubtitle:"Download the best apps and games",bannerImage:"",bannerLink:"",bannerEnabled:true,showFeatured:true,showTopCharts:true,dynamicCategories:"Action,RPG,Tools,Utilities,Communication,Social,Entertainment",hideSearchBar:false,hideLoginButton:false,headerCustomHTML:"",appListStyle:"grid",showRatingsOnCards:true,showDownloadsOnCards:true,detailExternalLinkText:"Download from MediaFire",showTechInfo:true,showRelatedApps:true,detailCustomHTML:"",preferExternalLinks:true,metaTitle:"VELORA HUB - Download APKs",metaDescription:"Download apps for Android, Windows, Mac",metaKeywords:"apps, apk, download, velora",ogImage:"",googleAnalyticsId:"",googleTagManagerId:"",maintenanceMode:false,disableRegistrations:false,disableRightClick:false,maxUploadSize:"500",showBannerAds:true,adClientId:"",headerAdHtml:"",homepageAdHtml:"",detailTopAdHtml:"",detailBottomAdHtml:"",customAdHtml:"",copyrightText:"© 2024 VELORA HUB",footerLinks:"Privacy Policy:/privacy, Terms:/terms",footerCustomHTML:"",socialFacebook:"",socialTwitter:"",socialTelegram:"",socialInstagram:"",privacyPolicy:"",termsOfService:"",cookieNoticeText:"",cookieNoticeEnabled:false,adminPassword:"",onesignalAppId:"",googleClientId:GOOGLE_CLIENT_ID,facebookAppId:FACEBOOK_APP_ID};
function getSettings(){var c=readJSON(SETTINGS_FILE,defaultSettings);var r={};Object.keys(defaultSettings).forEach(function(k){r[k]=defaultSettings[k]});Object.keys(c).forEach(function(k){r[k]=c[k]});return r}

function userAuth(req,res,next){var token=req.headers['authorization']?req.headers['authorization'].replace('Bearer ',''):'';if(!token)return res.status(401).json({error:'Login required'});var users=readJSON(USERS_FILE);var user=users.find(function(u){return u.token===token});if(!user||user.blocked)return res.status(401).json({error:'Invalid session'});req.user=user;next()}
function adminAuth(req,res,next){if((req.headers['x-admin-pass']||req.query.pass)===ADMIN_PASS)return next();res.status(401).json({error:'Wrong admin password'})}

// ─── OAUTH SETUP ───
var passport;
if(GOOGLE_CLIENT_ID || FACEBOOK_APP_ID){
    try{
        passport=require('passport');
        var GoogleStrategy=require('passport-google-oauth20').Strategy;
        var FacebookStrategy=require('passport-facebook').Strategy;
        
        app.use(passport.initialize());
        app.use(passport.session());
        
        passport.serializeUser(function(user,done){done(null,user.id)});
        passport.deserializeUser(function(id,done){var users=readJSON(USERS_FILE);var user=users.find(function(u){return u.id===id});done(null,user||null)});
        
        if(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET){
            passport.use(new GoogleStrategy({clientID:GOOGLE_CLIENT_ID,clientSecret:GOOGLE_CLIENT_SECRET,callbackURL:BASE_URL+'/auth/google/callback'},function(accessToken,refreshToken,profile,done){
                var users=readJSON(USERS_FILE);var user=users.find(function(u){return u.googleId===profile.id});
                if(!user){user={id:uuidv4(),name:profile.displayName,email:profile.emails&&profile.emails[0]?profile.emails[0].value:'',password:uuidv4(),token:uuidv4(),googleId:profile.id,googleToken:accessToken,installedApps:[],wishlist:[],avatar:profile.displayName.charAt(0).toUpperCase(),role:'user',blocked:false,joinedAt:new Date().toISOString()};users.push(user);writeJSON(USERS_FILE,users)}
                else{user.token=uuidv4();writeJSON(USERS_FILE,users)}
                return done(null,user)
            }));
            console.log('✅ Google OAuth configured');
        }
        
        if(FACEBOOK_APP_ID && FACEBOOK_APP_SECRET){
            passport.use(new FacebookStrategy({clientID:FACEBOOK_APP_ID,clientSecret:FACEBOOK_APP_SECRET,callbackURL:BASE_URL+'/auth/facebook/callback',profileFields:['id','displayName','emails']},function(accessToken,refreshToken,profile,done){
                var users=readJSON(USERS_FILE);var user=users.find(function(u){return u.facebookId===profile.id});
                if(!user){user={id:uuidv4(),name:profile.displayName,email:profile.emails&&profile.emails[0]?profile.emails[0].value:'',password:uuidv4(),token:uuidv4(),facebookId:profile.id,facebookToken:accessToken,installedApps:[],wishlist:[],avatar:profile.displayName.charAt(0).toUpperCase(),role:'user',blocked:false,joinedAt:new Date().toISOString()};users.push(user);writeJSON(USERS_FILE,users)}
                else{user.token=uuidv4();writeJSON(USERS_FILE,users)}
                return done(null,user)
            }));
            console.log('✅ Facebook OAuth configured');
        }
    }catch(e){console.log('⚠ Passport not installed, OAuth disabled:',e.message)}
}

// OAuth Routes
if(GOOGLE_CLIENT_ID){app.get('/auth/google',passport.authenticate('google',{scope:['profile','email']}));app.get('/auth/google/callback',passport.authenticate('google',{failureRedirect:'/'}),function(req,res){res.redirect('/#token='+req.user.token)})}
if(FACEBOOK_APP_ID){app.get('/auth/facebook',passport.authenticate('facebook',{scope:['email']}));app.get('/auth/facebook/callback',passport.authenticate('facebook',{failureRedirect:'/'}),function(req,res){res.redirect('/#token='+req.user.token)})}

// ─── PUBLIC ───
app.get('/api/settings',function(req,res){var s=getSettings();if(s.maintenanceMode&&!req.query.admin)return res.json({maintenanceMode:true,storeName:s.storeName,primaryColor:s.primaryColor});res.json(s)});
app.get('/api/apps',function(req,res){var apps=readJSON(DATA_FILE);if(req.query.category&&req.query.category!=='All')apps=apps.filter(function(a){return a.category===req.query.category});if(req.query.platform&&req.query.platform!=='All')apps=apps.filter(function(a){return a.platform&&a.platform.includes(req.query.platform)});if(req.query.search){var q=req.query.search.toLowerCase();apps=apps.filter(function(a){return[a.name,a.developer,a.category,a.description,a.shortDesc].some(function(s){return s&&s.toLowerCase().includes(q)})})}if(req.query.featured==='true')apps=apps.filter(function(a){return a.featured});apps.sort(function(a,b){return b.downloads-a.downloads});res.json(apps)});
app.get('/api/apps/:id',function(req,res){var app=readJSON(DATA_FILE).find(function(a){return a.id===req.params.id});if(!app)return res.status(404).json({error:'Not found'});res.json(app)});
app.get('/api/download/:id',function(req,res){var apps=readJSON(DATA_FILE);var app=apps.find(function(a){return a.id===req.params.id});if(!app||!app.apkFile)return res.status(404).json({error:'File missing'});var filePath=path.join(__dirname,app.apkFile);if(!fs.existsSync(filePath))return res.status(404).json({error:'File lost'});app.downloads=(app.downloads||0)+1;writeJSON(DATA_FILE,apps);res.download(filePath,app.apkOriginalName||path.basename(filePath))});

// ─── AUTH ───
app.post('/api/auth/register',sec.authLimiter,function(req,res){if(getSettings().disableRegistrations)return res.status(400).json({error:'Registrations disabled'});var name=req.body.name,email=req.body.email,password=req.body.password;if(!name||!email||!password)return res.status(400).json({error:'Fill all fields'});var users=readJSON(USERS_FILE);if(users.find(function(u){return u.email===email}))return res.status(400).json({error:'Email exists'});var user={id:uuidv4(),name:name,email:email,password:password,token:uuidv4(),installedApps:[],wishlist:[],avatar:name.charAt(0).toUpperCase(),role:'user',blocked:false,joinedAt:new Date().toISOString()};users.push(user);writeJSON(USERS_FILE,users);res.json({token:user.token,user:{id:user.id,name:user.name,email:user.email,avatar:user.avatar}})});
app.post('/api/auth/login',sec.authLimiter,sec.bruteForceGuard,function(req,res){var email=req.body.email,password=req.body.password;var users=readJSON(USERS_FILE);var user=users.find(function(u){return u.email===email&&u.password===password});if(!user){sec.trackFail(req.ip);return res.status(400).json({error:'Wrong email or password'})}if(user.blocked)return res.status(400).json({error:'Account suspended'});sec.resetFail(req.ip);user.token=uuidv4();writeJSON(USERS_FILE,users);res.json({token:user.token,user:{id:user.id,name:user.name,email:user.email,avatar:user.avatar}})});
app.get('/api/auth/me',userAuth,function(req,res){var u=req.user;res.json({id:u.id,name:u.name,email:u.email,avatar:u.avatar,installedApps:u.installedApps||[],wishlist:u.wishlist||[]})});
app.post('/api/apps/:id/wishlist',userAuth,function(req,res){var users=readJSON(USERS_FILE);var user=users.find(function(u){return u.id===req.user.id});if(!user.wishlist)user.wishlist=[];var idx=user.wishlist.indexOf(req.params.id);if(idx>-1)user.wishlist.splice(idx,1);else user.wishlist.push(req.params.id);writeJSON(USERS_FILE,users);res.json({success:true,wishlist:user.wishlist})});
app.post('/api/apps/:id/review',userAuth,function(req,res){var apps=readJSON(DATA_FILE);var app=apps.find(function(a){return a.id===req.params.id});if(!app)return res.status(404).json({error:'Not found'});var review={id:uuidv4(),userId:req.user.id,userName:req.user.name,avatar:req.user.avatar,rating:req.body.rating,text:req.body.text,date:new Date().toISOString()};if(!app.reviews)app.reviews=[];app.reviews.push(review);app.rating=parseFloat((app.reviews.reduce(function(s,r){return s+r.rating},0)/app.reviews.length).toFixed(1));writeJSON(DATA_FILE,apps);res.json({success:true,review:review})});

// ─── ADMIN ───
app.post('/api/admin/login',sec.authLimiter,sec.bruteForceGuard,function(req,res){if(req.body.password===ADMIN_PASS){sec.resetFail(req.ip);res.json({success:true})}else{sec.trackFail(req.ip);res.status(401).json({error:'Wrong password'})}});
app.get('/api/admin/stats',adminAuth,function(req,res){var apps=readJSON(DATA_FILE);var users=readJSON(USERS_FILE);res.json({totalApps:apps.length,totalUsers:users.length,totalDownloads:apps.reduce(function(s,a){return s+a.downloads},0),totalReviews:apps.reduce(function(s,a){return s+(a.reviews?a.reviews.length:0)},0),totalFiles:apps.filter(function(a){return a.apkFile}).length})});
app.get('/api/admin/settings',adminAuth,function(req,res){res.json(getSettings())});
app.post('/api/admin/settings',adminAuth,function(req,res){var current=getSettings();var n={};Object.keys(current).forEach(function(k){n[k]=current[k]});Object.keys(req.body).forEach(function(k){n[k]=req.body[k]});writeJSON(SETTINGS_FILE,n);if(n.adminPassword&&n.adminPassword.length>2)ADMIN_PASS=n.adminPassword;res.json({success:true})});
app.post('/api/admin/logo',adminAuth,upload.single('logo'),function(req,res){if(!req.file)return res.status(400).json({error:'No file'});var current=getSettings();current.logoUrl='/uploads/'+req.file.filename;writeJSON(SETTINGS_FILE,current);res.json({success:true,logoUrl:current.logoUrl})});
app.post('/api/admin/notify',adminAuth,function(req,res){res.json({success:true})});
app.get('/api/admin/presets',adminAuth,function(req,res){res.json(readJSON(PRESETS_FILE))});
app.post('/api/admin/presets',adminAuth,function(req,res){var presets=readJSON(PRESETS_FILE);presets.push({id:uuidv4(),name:req.body.name,settings:getSettings(),createdAt:new Date().toISOString()});writeJSON(PRESETS_FILE,presets);res.json({success:true})});
app.post('/api/admin/presets/:id/load',adminAuth,function(req,res){var presets=readJSON(PRESETS_FILE);var preset=presets.find(function(p){return p.id===req.params.id});if(!preset)return res.status(404).json({error:'Not found'});writeJSON(SETTINGS_FILE,preset.settings);res.json({success:true})});
app.delete('/api/admin/presets/:id',adminAuth,function(req,res){writeJSON(PRESETS_FILE,readJSON(PRESETS_FILE).filter(function(p){return p.id!==req.params.id}));res.json({success:true})});
app.get('/api/admin/users',adminAuth,function(req,res){res.json(readJSON(USERS_FILE).map(function(u){return{id:u.id,name:u.name,email:u.email,role:u.role,blocked:u.blocked,joinedAt:u.joinedAt,installedApps:u.installedApps?u.installedApps.length:0,wishlist:u.wishlist?u.wishlist.length:0}}))});
app.post('/api/admin/users/:id/block',adminAuth,function(req,res){var users=readJSON(USERS_FILE);var user=users.find(function(u){return u.id===req.params.id});if(user){user.blocked=!user.blocked;writeJSON(USERS_FILE,users)}res.json({success:true})});
app.delete('/api/admin/users/:id',adminAuth,function(req,res){writeJSON(USERS_FILE,readJSON(USERS_FILE).filter(function(u){return u.id!==req.params.id}));res.json({success:true})});
app.get('/api/admin/reviews',adminAuth,function(req,res){var all=[];readJSON(DATA_FILE).forEach(function(app){(app.reviews||[]).forEach(function(r){all.push({id:r.id,userName:r.userName,rating:r.rating,text:r.text,date:r.date,appName:app.name,appId:app.id})})});res.json(all.sort(function(a,b){return new Date(b.date)-new Date(a.date)}))});
app.delete('/api/admin/reviews/:appId/:reviewId',adminAuth,function(req,res){var apps=readJSON(DATA_FILE);var app=apps.find(function(a){return a.id===req.params.appId});if(app&&app.reviews){app.reviews=app.reviews.filter(function(r){return r.id!==req.params.reviewId});app.rating=app.reviews.length>0?parseFloat((app.reviews.reduce(function(s,r){return s+r.rating},0)/app.reviews.length).toFixed(1)):0;writeJSON(DATA_FILE,apps)}res.json({success:true})});

// APPS CRUD
app.post('/api/admin/apps',adminAuth,upload.fields([{name:'icon',maxCount:1},{name:'apk',maxCount:1},{name:'screenshots',maxCount:5}]),function(req,res){var apps=readJSON(DATA_FILE);var app={id:uuidv4(),name:req.body.name||'Untitled',developer:req.body.developer||'Unknown',category:req.body.category||'Tools',platform:req.body.platform||'Android',description:req.body.description||'',shortDesc:req.body.shortDesc||'',whatsNew:req.body.whatsNew||'',version:req.body.version||'1.0.0',size:req.body.size||'0 MB',rating:parseFloat(req.body.rating)||0,tags:req.body.tags?req.body.tags.split(',').map(function(t){return t.trim()}):[],externalLink:req.body.externalLink||'',icon:req.files.icon?'/uploads/icons/'+req.files.icon[0].filename:'',apkFile:req.files.apk?'/uploads/apks/'+req.files.apk[0].filename:'',apkOriginalName:req.files.apk?req.files.apk[0].originalname:'',screenshots:req.files.screenshots?req.files.screenshots.map(function(f){return'/uploads/screenshots/'+f.filename}):[],downloads:parseInt(req.body.downloads)||0,featured:req.body.featured==='true',reviews:[],createdAt:new Date().toISOString()};apps.push(app);writeJSON(DATA_FILE,apps);res.json({success:true,app:app})});
app.put('/api/admin/apps/:id',adminAuth,upload.fields([{name:'icon',maxCount:1},{name:'apk',maxCount:1},{name:'screenshots',maxCount:5}]),function(req,res){var apps=readJSON(DATA_FILE);var app=apps.find(function(a){return a.id===req.params.id});if(!app)return res.status(404).json({error:'Not found'});Object.keys(req.body).forEach(function(k){if(k==='tags')app[k]=req.body[k].split(',').map(function(t){return t.trim()});else app[k]=req.body[k]});if(req.body.rating)app.rating=parseFloat(req.body.rating);if(req.body.downloads)app.downloads=parseInt(req.body.downloads);if(req.body.featured)app.featured=req.body.featured==='true';if(req.files&&req.files.icon)app.icon='/uploads/icons/'+req.files.icon[0].filename;if(req.files&&req.files.apk){app.apkFile='/uploads/apks/'+req.files.apk[0].filename;app.apkOriginalName=req.files.apk[0].originalname}if(req.files&&req.files.screenshots)app.screenshots=req.files.screenshots.map(function(f){return'/uploads/screenshots/'+f.filename});writeJSON(DATA_FILE,apps);res.json({success:true,app:app})});
app.delete('/api/admin/apps/:id',adminAuth,function(req,res){var apps=readJSON(DATA_FILE);var app=apps.find(function(a){return a.id===req.params.id});if(!app)return res.status(404).json({error:'Not found'});[app.icon,app.apkFile].concat(app.screenshots||[]).forEach(function(f){if(f){var p=path.join(__dirname,f);if(fs.existsSync(p))fs.unlinkSync(p)}});apps=apps.filter(function(a){return a.id!==req.params.id});writeJSON(DATA_FILE,apps);res.json({success:true})});

app.get('/admin',function(req,res){res.sendFile(path.join(__dirname,'public','admin.html'))});

if(!fs.existsSync(DATA_FILE)||readJSON(DATA_FILE).length===0){writeJSON(DATA_FILE,[{id:'s1',name:'Zytor',developer:'Velora Team',category:'Tools',platform:'Android',description:'All in one downloader tool.',shortDesc:'All in one downloader',whatsNew:'Speed improvements',version:'3.2.1',size:'25 MB',rating:4.5,tags:['Tools','Downloader'],externalLink:'',icon:'',apkFile:'',screenshots:[],downloads:150000,featured:true,reviews:[],createdAt:new Date().toISOString()},{id:'s2',name:'Free Fire MAX',developer:'Garena',category:'Action',platform:'Android',description:'Premium Battle Royale experience.',shortDesc:'Battle Royale',whatsNew:'New skins',version:'2.0.1',size:'500 MB',rating:4.3,tags:['Action'],externalLink:'https://www.mediafire.com',icon:'',apkFile:'',screenshots:[],downloads:5000000,featured:true,reviews:[],createdAt:new Date().toISOString()}])}

app.listen(PORT,'0.0.0.0',function(){console.log('\n  ✅ VELORA HUB running on http://localhost:'+PORT);console.log('  🔧 Admin: http://localhost:'+PORT+'/admin');if(GOOGLE_CLIENT_ID)console.log('  🔵 Google OAuth: ACTIVE');if(FACEBOOK_APP_ID)console.log('  🔵 Facebook OAuth: ACTIVE');if(!GOOGLE_CLIENT_ID&&!FACEBOOK_APP_ID)console.log('  ⚠️  OAuth not configured - see README');console.log('')});
