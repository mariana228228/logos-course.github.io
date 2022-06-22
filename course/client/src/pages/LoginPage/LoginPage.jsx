import {useDispatch, useSelector} from 'react-redux';
import {Schema} from "rsuite";
import {useEffect, useRef, useState} from "react";
import {loginUser} from "../../redux/reducers/authReducer";
import LogForm from "./LoginForm/LogForm";
import {toast} from "react-toastify";
import {actionUsers} from "../../redux/actionsCreator/authCreator";
import {useNavigate} from "react-router-dom";


const LoginPage = () => {
        const dispatch = useDispatch()
        const {errorUsers} = useSelector((state) => state.authReducer)
    const navigate = useNavigate()

        const redirect = () => {
            navigate('/register')
        }
        const {StringType} = Schema.Types;
        const formRef = useRef();
        const [formError, setFormError] = useState({});
        const [formValue, setFormValue] = useState({
            email: "",
            password: "",
        });

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
            if (!formRef.current.check()) {
                return;
            }
            dispatch(loginUser({...formValue}))

        }
        const model = Schema.Model({
            email: StringType()
                .isRequired('This field is required.')
                .isEmail( 'It is not email'),
            password: StringType()
                .minLength(8, 'Password is too short')
                .isRequired('This field is required.'),
        });


    return (
        <LogForm
            formValue={formValue}
            setFormValue={setFormValue}
            formError={formError}
            setFormError={setFormError}
            formRef={formRef}
            handleSubmit={handleSubmit}
            formModel={model}
            redirect={redirect}
        />
    )
}

export default LoginPage;
