import { asyncHandler } from "../../utils/asyncHandler.js";
import { ApiError } from "../../utils/ApiError.js";
import { ApiResponse } from "../../utils/ApiResponse.js";
import jwt from "jsonwebtoken";
import { User } from "../../models/user.model.js";
import { Transaction } from "../../models/transaction.modal.js";
const tempAdmin = new Map();

const generateAccessAndRefereshTokens = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      "Something went wrong while generating referesh and access token"
    );
  }
};

const dashboredAdmin = asyncHandler(async (req, res) => {
  const totalUsers = await User.countDocuments(); // Get total user count

  const today = new Date();
  const startOfDay = new Date(
    today.getFullYear(),
    today.getMonth(),
    today.getDate()
  );
  const endOfDay = new Date(
    today.getFullYear(),
    today.getMonth(),
    today.getDate() + 1
  );

  // Get today's new users count
  const newUsersToday = await User.countDocuments({
    createdAt: {
      $gte: startOfDay,
      $lt: endOfDay,
    },
  });
  const newPendingTransactionsToday = await Transaction.countDocuments({
    transactionStatus: "Pending",
    createdAt: {
      $gte: startOfDay,
      $lt: endOfDay,
    },
  });

  return res.render("pages/dashboard", {
    totalUsers, // Pass total user count
    newUsersToday, // Pass today's new users count
    newPendingTransactionsToday,
    currentPage: "dashboard",

  });
});

const getLoginAdmin = async (req, res) => {
  try {
    let { accessToken } = req.cookies;
    try {
      let decoded = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
      req.user = await User.findOne({ _id: decoded });
      if (req.user.userType == 1) {
        return res.redirect("/");
      } else {
        return res.render("pages/login", { error: null });
      }
    } catch (error) {
      return res.render("pages/login", { error: null });
    }
  } catch (error) {
    return res.render("pages/login", { error: null });
  }
};

const loginAdmin = asyncHandler(async (req, res) => {
  const { phone_no } = req.body;
  if (!phone_no || phone_no.trim() === "") {
    return res.render("pages/login", {
      error: "Phone number is required",
      phone_no: null,
    });
    // return res.status(400).json(new ApiError(400, "Phone number is required", ["Phone number is required"]));
  }

  // Check if the phone number exists in the admin users collection
  const user = await User.findOne({
    phone_no,
    userType: 1, // Assuming 1 represents admin user type
  });
  if (!user) {
    return res.render("pages/login", {
      error: "User with this phone number does not exist or is not an admin",
      phone_no: null,
    });

    // return res.status(404).json(new ApiError(404, "User with this phone number does not exist or is not an admin", ["User with this phone number does not exist or is not an admin"]));
  }

  try {
    // Generate and send OTP
    const { otp, messageSid } = await otpService.requestOtp(phone_no);
    tempAdmin.set(phone_no, {
      phone_no,
      otp,
      otpExpiresAt: Date.now() + 10 * 60 * 1000, // OTP valid for 10 minutes
    });
    console.log("otp", otp);
    return res.render("pages/verifyOtp", { error: null, phone_no: phone_no ,otp});
    // return res.render("pages/verifyOtp", { error: null, phone_no })
  } catch (error) {
    return res.render("pages/login", {
      error: "Failed to send OTP",
      phone_no: null,
    });

    // return res.status(500).json(new ApiError(500, "Failed to send OTP", [error.message]));
  }
});

const logoutAdmin = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.admin._id,
    {
      $unset: {
        refreshToken: 1, // this removes the field from document
      },
    },
    {
      new: true,
    }
  );

  const options = {
    httpOnly: true,
    secure: false,
  };
  console.log("logouttt");
  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .redirect("/");
});

const verifyOtpAdmin = asyncHandler(async (req, res) => {
  const { phone_no, otp } = req.body;
  const temporaryAdmin = tempAdmin.get(phone_no);
  if (
    !temporaryAdmin ||
    temporaryAdmin.otp !== otp ||
    temporaryAdmin.otpExpiresAt < Date.now()
  ) {
    return res.render("pages/verifyOtp", {
      error: "Invalid or expired OTP",
      phone_no: phone_no,
      otp: null,
    });
    // return res.status(400).json(new ApiError(400, "Invalid or expired OTP", ["Invalid or expired OTP"]));
  }
  let user = await User.findOne({ phone_no });
  // Clear temporary OTP data
  tempAdmin.delete(phone_no);

  // Generate access token for the admin
  const { accessToken, refreshToken } = await generateAccessAndRefereshTokens(
    user._id
  ); // You can adjust this function based on your requirements

  const options = {
    httpOnly: true,
    secure: false,
  };
  console.log({ accessToken, refreshToken });

  // Respond with the tokens
  res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options);
  return res.redirect("/");
});


const deleteUser = asyncHandler(async (req, res) => {
  const { userId } = req.body; // Assuming userId is passed as a URL parameter
  try {
    const user = await User.findByIdAndDelete(userId); // Use findByIdAndDelete for Mongoose
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.status(200).json({ message: "User deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting user", error });
  }
});





export {
  loginAdmin,
  logoutAdmin,
  getLoginAdmin,
  dashboredAdmin,
  verifyOtpAdmin,
  deleteUser,
};
