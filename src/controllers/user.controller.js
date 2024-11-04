import { asyncHandler } from "../utils/asyncHandler.js";
import {ApiError} from "../utils/ApiError.js"
import { User} from "../models/user.model.js"
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken"
import mongoose from "mongoose";

const tempUsers = new Map();

const generateAccessAndRefereshTokens = async(userId) =>{
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false })

        return {accessToken, refreshToken}


    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating referesh and access token")
    }
}

// refreshAccessToken
const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    if (!incomingRefreshToken) {
        throw new ApiError(401, "unauthorized request")
    }

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )
    
        const user = await User.findById(decodedToken?._id)
    
        if (!user) {
            throw new ApiError(401, "Invalid refresh token")
        }
    
        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "Refresh token is expired or used")
            
        }
    
        const options = {
            httpOnly: true,
            secure: true
        }
    
        const {accessToken, newRefreshToken} = await generateAccessAndRefereshTokens(user._id)
    
        return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", newRefreshToken, options)
        .json(
            new ApiResponse(
                200, 
                {accessToken, refreshToken: newRefreshToken},
                "Access token refreshed"
            )
        )
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token")
    }

})

//logout 
const logoutUser = asyncHandler(async(req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $unset: {
                refreshToken: 1 // this removes the field from document
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged Out"))
})

//register user
const registerUser = asyncHandler(async (req, res) => {
    const { phone_no } = req.body;
   
    if ([phone_no].some(field => !field || field?.trim() === "")) {
        return res.status(400).json(new ApiError(409, "Phone number is required", ["Phone number is required"]))
    }


    const existedUser = await User.findOne({ $or: [{ phone_no }] });

    if (existedUser) {
        return res.status(409).json(new ApiError(409, "User with Phone number already exists", ["User with Phone number already exists"]))
    }
    try{
        const { otp, messageSid } = await otpService.requestOtp(phone_no);
        tempUsers.set(phone_no, {
            phone_no,
            otp,
            otpExpiresAt: Date.now() + 10 * 60 * 1000 // OTP valid for 10 minutes
        });
        return res.status(201).json(new ApiResponse(200, { phone_no, otp }, "OTP sent successfully"));
    }catch(error){
        return res.status(500).json(new ApiError(500, "Failed to send OTP", [error.message]));
    }
});

//verifyOtp
const verifyOtp = asyncHandler(async (req, res) => {
    const { phone_no, otp } = req.body;
    const temporaryUser = tempUsers.get(phone_no);
    
    if (!temporaryUser || temporaryUser.otp !== otp || temporaryUser.otpExpiresAt < Date.now()) {
        return res.status(400).json(new ApiError(400, "Invalid or expired passcode", ["Invalid or expired passcode"]));
    }

    // Check if the user is already registered
    let user = await User.findOne({ phone_no });

    if (user) {
        // User is already registered, update the account status and generate tokens
        const { accessToken, refreshToken } = await generateAccessAndRefereshTokens(user._id);

        // user.userAccountStatus = "logged in"; // Update account status to 'logged in'
        user.refreshToken = refreshToken; // Save refreshToken to user document
        await user.save();

        // Clear temporary OTP data
        tempUsers.delete(phone_no);

        const options = {
            httpOnly: true,
            secure: true
        }
        const userData = await User.findById(user._id).select("-password -refreshToken -plaidAccessToken -plaidItemID -processorToken -accountIds");

        return res.status(200).cookie("accessToken", accessToken, options)
            .cookie("refreshToken", refreshToken, options).json(new ApiResponse(200, {
                user: userData,
                userAccountStatus: user.userAccountStatus,
                accessToken,
            }, "User logged in successfully"));
    } else {
        // User is not registered, create a new user
        user = await User.create({ phone_no, userAccountStatus: "registered" });

        const createdUser = await User.findById(user._id).select("-password -refreshToken");

        if (!createdUser) {
            return res.status(500).json(new ApiError(500, "Something went wrong while registering the user", ["Something went wrong while registering the user"]));
        }

        const { accessToken, refreshToken } = await generateAccessAndRefereshTokens(user._id);

        // Update user with the tokens and account status
        // createdUser.userAccountStatus = "registered"; // Set account status to 'registered'
        createdUser.refreshToken = refreshToken;
        await createdUser.save();

        // Clear temporary OTP data
        tempUsers.delete(phone_no);

        const options = {
            httpOnly: true,
            secure: true
        }
        const userData = await User.findById(user._id).select("-password -refreshToken -plaidAccessToken -plaidItemID -processorToken -accountIds");

        return res.status(201).cookie("accessToken", accessToken, options)
            .cookie("refreshToken", refreshToken, options).json(new ApiResponse(201, {
                user: userData,
                userAccountStatus: createdUser.userAccountStatus,
                accessToken,
            }, "User registered successfully"));
    }
});

//login
const login = asyncHandler(async (req, res) => {
    const { phone_no, resend } = req.body;

    if (!phone_no || phone_no.trim() === "") {
        return res.status(400).json(new ApiError(400, "Phone number is required", ["Phone number is required"]));
    }

    if (resend) {
        try {
            const { otp, messageSid } = await otpService.requestOtp(phone_no);
            tempAdmin.set(phone_no, {
                phone_no,
                otp,
                otpExpiresAt: Date.now() + 10 * 60 * 1000 // OTP valid for 10 minutes
            });
            return res.status(200).json(new ApiResponse(200, { phone_no, otp }, "OTP resent successfully"));
        } catch (error) {
            return res.status(500).json(new ApiError(500, "Failed to resend OTP", [error.message]));
        }
    }

    // Regular flow to check user existence and send OTP
    const existedUser = await User.findOne({ phone_no });
    if (!existedUser) {
        return res.status(404).json(new ApiError(404, "User with this phone number does not exist", ["User with this phone number does not exist"]));
    }

    try {
        const { otp, messageSid } = await otpService.requestOtp(phone_no);
        tempUsers.set(phone_no, {
            phone_no,
            otp,
            otpExpiresAt: Date.now() + 10 * 60 * 1000 // OTP valid for 10 minutes
        });
        return res.status(200).json(new ApiResponse(200, { phone_no, otp }, "OTP sent successfully"));
    } catch (error) {
        return res.status(500).json(new ApiError(500, "Failed to send OTP", [error.message]));
    }
});




export {
    registerUser,
    logoutUser,
    refreshAccessToken,
    verifyOtp,
    login
}