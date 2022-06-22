
import React from "react";
import style from "../../Form.module.css";
import keyImg from "../../img/key.png";
import {TextField} from "../../../components/RSUITE components/rsuiteComp"
import {Button, Form} from "rsuite";
import scss from '../../Navbar/Nav.module.scss'


const RegisterForm = ({FormValue,setFormValue,handleSubmit,model,formRef}) => {
    return(
        <section>
            <div className={style.container}>
                <div className={`${style.user} ${style.signupBx}`}>
                    <div className={style.imgBx}><img src={keyImg}/></div>
                    <div className={style.formBx}>
                        <Form
                            ref={formRef}
                            formValue={FormValue}
                            onChange = {setFormValue}
                            model={model}>

                            <TextField name='username' label = 'Your name' />
                            <TextField name='email' label = 'Your email' />
                            <TextField type='password' name='password' label = 'Your password' />
                            <Form.Group>
                                <Button className={`${scss.btn} ${scss.thirdRegister}`} onClick={handleSubmit}>
                                    Submit </Button>
                            </Form.Group>
                        </Form>
                            <p className={style.signup}>Maybe you don't have an account? <a href="/login">Sign in</a></p>
                    </div>
                </div>
            </div>
        </section>
    )}

export default RegisterForm;