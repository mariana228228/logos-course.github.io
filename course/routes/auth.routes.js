const {Router} = require('express')
const bcrypt = require('bcryptjs')
const config = require('config')
const jwt = require('jsonwebtoken')
const {check, validationResult} = require('express-validator')
const User = require('../models/User')
const authMiddleware = require("../middlewares/auth.middleware");
const router = Router()
const multer = require( 'multer')


const storage = multer.diskStorage({
    destination:function (req,file,cb){
        cb(null,'./uploads/')

    },
    filename:function (req,file,cb){
        const parts = file.mimetype.split('/')
        const ext = `.` + parts[parts.length - 1]
        cb(null,req.user.userId + ext)
    }
})
const fileFilter = (req,file,cb) => {
    // reject a file
    if(file.mimetype === 'image/jpeg' || file.mimetype === 'image/png'){
        cb(null,true);
    }else{
        cb(null,false);
    }


}
const upload = multer({
    storage:storage,
    limits:{
        fileSize : 1024 * 1024 * 5},
    fileFilter:fileFilter
})
router.post(
    '/register',
    [
        check('email', 'Некоректний email').isEmail(),
        check('password', 'Мінімальна довжина - 6 символів')
            .isLength({ min: 6 }),
        check('username', 'Мінімальна довжина - 2 букви')
            .isLength({ min: 2 }),
    ],
    async (req, res) => {
        try {
            console.log(req.body)
            const errors = validationResult(req)
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    errors: errors.array(),
                    message: 'Некоретні данні при реєстрації'
                })
            }

            const { email, password, username } = req.body

            const candidate = await User.findOne({ email })
            const checkUsername = await User.findOne({username: username.toLowerCase()})

            if(checkUsername){
                return res.status(400).json({ message : 'Цей нік вже зайнятий'})
            }
            if (candidate) {
                return res.status(400).json({ message: 'Такий користувач вже є' })
            }

            const hashedPassword = await bcrypt.hash(password, 12)
            const user = new User({ email:email.toLowerCase(),
                password: hashedPassword,
                username: username.toLowerCase() })

            await user.save()
            res.status(201).json({ message: 'Користувач створений' })
        } catch (e) {
            res.status(500).json({ message: 'Mistake is here' })
        }
    })
router.post(
    '/login',
    [
      check('email', 'Введіть коректний email').normalizeEmail().isEmail(),
      check('password', 'Введіть пароль').exists()
    ],
    async (req, res, id) => {
            try{
                const errors = validationResult(req)

                if(!errors.isEmpty()){
                    return res.status(400).json({
                        errors: errors.array(),
                        message: 'Неправильні дані при вході в систему'
                    })
                }

                const {email, password} = req.body

                const user = await  User.findOne({email})

                if(!user){
                    return res.status(400).json({message: 'Користувача не знайдено'})
                }

                const isMatch = await bcrypt.compare(password, user.password)

                if(!isMatch){
                    return res.status(400).json({message: 'Неправильний пароль попробуйте знову'})
                }

                const token = jwt.sign(
                    { userId: user.id},
                    config.get('jwtSecret'),
                    { expiresIn: '1h' }
                )

                res.json({
                    message: true ,
                    username: user.username,
                    email: user.email,
                    token,
                    userID : user.id})

            }catch (e){
                res.status(500).json({message: 'Щось пішло не так, попробуйте знову'})
            }
})

router.post('/check',
    authMiddleware, (req, res) => {
        res.status(204).send()
    })

router.post('/image/post',[authMiddleware,upload.single('file')],async (req,res) => {
    try{
        const user = await User.findById(req.user.userId)
        user.userImage = `http://localhost:5000/uploads/${req.file.filename}`
        await user.save()
        return res.status(201).json(user)
    }
    catch(e){
        res.status(500).json({
            message: 'Something went wrong, try again later'
        })
    }
})

router.get('/details', authMiddleware,async (req, res) => {
    try {
        const {userId} = req.query
        const user = await User.findById(userId,{ username:0,password:0})
        if(user){
            return res.status(201).json({user})
        }
        res.status(404).send('Not found')
    } catch (e) {
        res.status(500).json({
            message: 'Something went wrong, try again later'
        })
    }
})

module.exports = router


