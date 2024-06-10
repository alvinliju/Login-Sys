const express = require("express")
const path = require("node:path")
const session = require("express-session")
const mongoose = require("mongoose")
const MongoDbSession = require("connect-mongodb-session")(session)
const userModel = require("./models/user")
const bcrypt = require("bcryptjs")


//conectting mongo
const URI = "mongodb+srv://alvin:parayulla@cluster0.rt9pyk2.mongodb.net/Login_API?retryWrites=true&w=majority&appName=Cluster0"
mongoose.connect(URI)
.then(()=>console.log("db started"))
.catch(()=>console.log("error in connecting db"))


//storing session in mongodb
const store = new MongoDbSession({
  uri: URI,
  collection:'mySessions',
})

const app = express()

//view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

//middle wares
app.use(express.urlencoded({extended:true}))
app.use(express.json({extended:false}))

// init sessions
app.use(session({
  secret:'secrect key',
  resave:false,
  saveUninitalized:false,
  store:store
}))

// is auth for security
const isAuth = (req,res,next)=>{
  if(req.session.isAuth){
    next()
  }else{
    res.redirect('/login')
  }
}

// controlling redirects
const redirectIfAuthenticated = (req, res, next) => {
  if (req.session.isAuth) {
    return res.redirect('/home');
  }
  next();
};

// app.get('/',redirectIfAuthenticated,(req,res)=>{
//   req.session.isAuth = true;
//   req.session.redirectIfAuthenticated=true;
//   res.render('signup')
// })

//signup route
app.get('/',redirectIfAuthenticated,(req,res)=>{
  return res.redirect('/signup')
})

app.get('/signup',redirectIfAuthenticated,(req,res)=>{
  res.render('signup')
})

app.post('/signup',async (req,res)=>{
  const {username,password,email} = req.body

  let user = await userModel.findOne({email})
  if(user){
    return res.redirect('/login')
  }

  const hashedPsw = await bcrypt.hash(password,12)

  user = new userModel({
    username,
    email,
    password:hashedPsw
  })

  await user.save()
  req.session.IsLoggedIn=true
  res.redirect('/login')
})


//login route
app.get('/login',redirectIfAuthenticated,(req,res)=>{
  res.render('login')
})

app.post('/login',async (req,res)=>{
  const {email,password}=req.body
  const user = await userModel.findOne({email})
  if(!user){
    res.redirect('/signup')
  }
  const isMatch = await bcrypt.compare(password, user.password);

  if(!isMatch){
    return res.render('login',{ error: 'Invalid email or password' })
  }

  req.session.isAuth=true
  return res.redirect('/home')
})

//home route
app.get('/home',isAuth,(req,res)=>{
  res.render('home')
})

// logout route
app.post('/logout',(req,res)=>{
  req.session.destroy((err)=>{
    if(err) throw err;
    res.redirect('/home')
  })
})

app.listen(8000,()=>console.log("server started"))