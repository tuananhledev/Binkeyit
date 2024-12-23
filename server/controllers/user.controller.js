import sendEmail from '../config/sendEmail.js'
import UserModel from '../models/user.model.js'
import bcryptjs from 'bcryptjs'
import verifyEmailTemplate from '../utils/verifyEmailTemplate.js'
import generatedAccessToken from '../utils/generatedAccessToken.js'
import generatedRefreshToken from '../utils/generatedRefreshToken.js'
import uploadImageClodinary from '../utils/uploadImageClodinary.js'

export async function registerUserController(req,res) {
    try{
        const {name,email,password}=req.body

        if(!name||!email||!password){
            return res.status(400).json({
                message:"provide email, name, password",
                error:true,
                success:false
            })
        }

        const user = await UserModel.findOne({email})

        if(user){
            return res.json({
                message:"Already register email",
                error:true,
                success:false
            })
        }

        const salt = await bcryptjs.genSalt(10)
        const hashPassword =await bcryptjs.hash(password,salt)

        const payload={
            name,
            email,
            password:hashPassword
        }

        const newUser = new UserModel(payload)
        const save = await newUser.save()

        const verifyEmailUrl=`${process.env.FRONTEND_URL}/verify-email?code=${save?._id}`

        const verifyEmail =await sendEmail({
            sendTo:email,
            subject:"Verify email from Binkeyit",
            html:verifyEmailTemplate({
                name,
                url:verifyEmailUrl
            })
        })

        return res.json({
            message:"User register successfully",
            error:false,
            success:true,
            data:save
        })

    }catch(error){
        return res.status(500).json({
            message:error.message||error,
            error:true,
            success:false
        })
    }
}

export async function verifyEmailController(req,res) {
    try{
        const{code}=req.body

        const user=await UserModel.findOne({_id:code})

        if(!user){
            return res.status(400).json({
                message: "Invaild code",
                error:true,
                success:false
            })
        }

        const updateUser = await UserModel.updateOne({_id:code},{
            verify_email:true
        })

        return res.json({
            message: "Verify email done",
            success:true,
            error:false
        })

    }catch(error){
        return res.status(500).json({
            message: error.message || error,
            error: true,
            success:true
        })
    }
}

//login controller
export async function loginController(req,res) {
    try {
        const {email,password} = req.body

        if(!email || !password){
            return res.status(400).json({
                message:"provide email, password",
                error:true,
                success:false
            })
        }

        const user= await UserModel.findOne({email})

        if(!user){
            return res.status(400).json({
                message: "User not register",
                error: true,
                success: false
            })
        }

        if(user.status !== "Active"){
            return res.status(400).json({
                message: "Contact to Admin",
                error: true,
                success:false
            })
        }

        const checkPassword = await bcryptjs.compare(password,user.password)

        if(!checkPassword){
            return res.status(400).json({
                message: "Check your password",
                error: true,
                success: false
            })
        }

        const accessToken = await generatedAccessToken(user._id)
        const refreshToken = await generatedRefreshToken(user._id)

        const cookiesOption={
            httpOnly: true,
            secure: true,
            sameSite: "None"
        }

        res.cookie('accessToken',accessToken,cookiesOption)
        res.cookie('refreshToken',refreshToken,cookiesOption)

        return res.json({
            message:"Login successfully",
            error:false,
            success:true,
            data:{
                accessToken,
                refreshToken
            }
        })

    } catch (error) {
        return res.status(500).json({
            message: error.message || error,
            error:true,
            success:false 
        })
    }
}


//logout controller
export async function logoutController(req,res) {
    try {
        const userid = req.userId

        const cookieOption={
            httpOnly:true,
            secure:true,
            sameSite:"None"
        }

        res.clearCookie("accessToken",cookieOption)
        res.clearCookie("refreshToken",cookieOption)

        const removeRefreshToken = await UserModel.findByIdAndUpdate(userid,{
            refresh_token:""
        })

        return res.json({
            message:"Logout successfully",
            error:false,
            success:true
        })
    } catch (error) {
        return res.status(500).json({
            message: error.message || error,
            error: true,
            success: false
        })
    }
}


//upload user avatar
export async  function uploadAvatar(req,res){
    try {
        const userId = req.userId // auth middlware
        const image = req.file  // multer middleware

        const upload = await uploadImageClodinary(image)
        
        const updateUser = await UserModel.findByIdAndUpdate(userId,{
            avatar : upload.url
        })

        return res.json({
            message : "upload profile",
            success : true,
            error : false,
            data : {
                _id : userId,
                avatar : upload.url
            }
        })

    } catch (error) {
        return res.status(500).json({
            message : error.message || error,
            error : true,
            success : false
        })
    }
}




