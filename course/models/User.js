const {Schema, model} = require('mongoose')

const schema = new Schema({
    email: {type: String, required: true, unique: true},
    password:{type:String, require: true},
    username : {type:String,require: true},
    userImage: {type:String, default: ''}
})

module.exports = model('User', schema)