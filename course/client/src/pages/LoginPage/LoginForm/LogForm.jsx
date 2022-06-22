
import React from "react";
import style from "../../Form.module.css";
import img from "../../img/img.png";
import {TextField} from "../../../components/RSUITE components/rsuiteComp"
import {Button, Form} from "rsuite";
// import './RegisterPageStyle.css'
import scss from '../../Navbar/Nav.module.scss'


const LoginForm = ({FormValue,setFormValue,handleSubmit,model,formRef}) => {
    return(
        <section>
            <div className={style.container}>
                <div className={`${style.user} ${style.signupBx}`}>
                    <div className={style.imgBx}><img src={img}/></div>
                    <div className={style.formBx}>
                        <Form
                            ref={formRef}
                            formValue={FormValue}
                            onChange = {setFormValue}
                            model={model}>

                            <TextField name='email' label = 'Your email' />
                            <TextField type='password' name='password' label = 'Your password' />
                            <Form.Group>
                                <Button className={`${scss.btn} ${scss.third}`}onClick={handleSubmit}>
                                    Submit </Button>
                            </Form.Group>
                        </Form>
                        <p className={style.signup}>Already have an account? <a href="/register">Sign in</a></p>
                    </div>
                </div>
            </div>
        </section>
    )}

export default LoginForm;