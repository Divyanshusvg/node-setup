import mongoose, {Schema} from "mongoose";
import jwt from "jsonwebtoken"
import bcrypt from "bcrypt"
import mongooseAggregatePaginate from "mongoose-aggregate-paginate-v2";
const userSchema = new Schema(
    {   
        userName: {
            type: String
        },
        email: {
            type: String,
            // unique: true,
            trim: true,
        },
        phone_no: {
            type: String,
            required: true   
        },
        refreshToken: {
            type: String
        },
        businessName:{
            type: String
        },
        accountIds:{
            type:Array
        },
        plaidAccessToken:{
            type:String
        },
        checkingPlaidAccessToken:{
            type:String
        },
        savingPlaidAccessToken:{
            type:String
        },
        checkingPlaidItemID:{
            type:String
        },
        savingPlaidItemID:{
            type:String
        },
        plaidItemID:{
            type:String
        },
        userAccountStatus:{
            type:String,
            default:"registerd"
        },
        processorToken :{
            type:String
        },
        userType:{
            type:String,
            required: true,
            enum: [0,1],
            default:"0"  // 0 for user, 1 for admin
        },
        checkingAccount:{
            type:Object,
            default:null
        },
        SavingAccount:{
            type:Object,
            default:null
        },
        plaidUserToken:{
            type:String,
            default:null
        },
        plaidUserId:{
            type:String,
            default:null
        },
        todayCheckingBalance:{
            type:String,
            default:null
        },
        todaySavingBalance:{
            type:String,
            default:null
        },
        autoSweepLimit:{
            type:String,
            default:null
        },
        autoSweepFlag:{
            type:Boolean,
            default:false
        },
    },
    {
        timestamps: true
    }
)

userSchema.pre("save", async function (next) {
    if(!this.isModified("password")) return next();

    this.password = await bcrypt.hash(this.password, 10)
    next()
})

userSchema.methods.isPasswordCorrect = async function(password){
    return await bcrypt.compare(password, this.password)
}

userSchema.methods.generateAccessToken = function(){
    return jwt.sign(
        {
            _id: this._id,
            email: this.email,
            username: this.username,
            fullName: this.fullName
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY
        }
    )
}
userSchema.methods.generateRefreshToken = function(){
    return jwt.sign(
        {
            _id: this._id,
            
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRY
        }
    )
}
userSchema.plugin(mongooseAggregatePaginate)

export const User = mongoose.model("User", userSchema)