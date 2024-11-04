import express from "express"
import cors from "cors"
import cookieParser from "cookie-parser"
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url"
import expressEjsLayouts from "express-ejs-layouts"
dotenv.config();


const app = express()

app.use(cors({
    origin: ['http://83.136.219.131:8060' ,'http://localhost:8060'],
    credentials: true
}))


app.use(express.json({limit: "16kb"}))
app.use(express.urlencoded({extended: true, limit: "16kb"}))
app.use(express.static("public"))
app.use(cookieParser())
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Set the views directory and engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));
app.use(expressEjsLayouts)

app.locals.siteUrl = process.env.SITE_URL;
//routes import
import userRouter from './routes/user.routes.js'
import adminRouter from "./routes/admin.routes.js";

//routes declaration
app.use("/api/v1/users", userRouter)
app.use("/",adminRouter)
app.use(express.static('public')); 


export { app }