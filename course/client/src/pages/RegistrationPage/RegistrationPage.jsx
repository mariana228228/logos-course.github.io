import {useDispatch, useSelector} from 'react-redux';
import {Schema} from "rsuite";
import {useEffect, useRef, useState} from "react";
import RegisterPage from "./RegistrationForm/RegisterPage";
import {registerUser} from "../../redux/reducers/authReducer";
// import {useEffect} from "@types/react";
import {toast} from "react-toastify";
import {actionUsers} from "../../redux/actionsCreator/authCreator";



const RegistrationPage = () => {
    const dispatch = useDispatch();
    const {errorUsers} = useSelector((state) => state.authReducer)
    const formRef = useRef()

    const [FormValue,setFormValue] = useState({
        email:'',
        password:'',
        username:"",
    })

    useEffect(()=>{
        if(errorUsers){
            toast.error(errorUsers, {
                position: "top-center",
                autoClose: 5000,
                hideProgressBar: false,
                closeOnClick: true,
                pauseOnHover: true,
                draggable: true,
                onClose: () => {
                    dispatch(actionUsers.setErrors(''))
                }
            });
        }
    },[errorUsers])


    const handleSubmit = () => {
        if(!formRef.current.check()){
            return;
        }
            dispatch(registerUser({...FormValue}))
    }

    const {StringType} = Schema.Types;
    const model = Schema.Model({
        username: StringType().isRequired('This field is required.')
            .minLength(2,'A small number of characters'),
        email: StringType()
            .isEmail('Please enter a valid email address.')
            .isRequired('This field is required.'),
        password: StringType().isRequired('This field is required.')
            .minLength(4,'A small number of characters'),

    })

    return (
        <RegisterPage
            title="register"
            model = {model}
            handleSubmit={handleSubmit}
            FormValue = {FormValue}
            setFormValue={setFormValue}
            formRef={formRef}
        />
    )
}

export default RegistrationPage;
