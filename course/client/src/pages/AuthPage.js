import React, {useState} from "react";
import style from "./Form.module.css";
import img from "./img/img.png";
import {Link} from "react-router-dom";

export const AuthPage = () => {

    const [form, setForm] = useState({
        email: '',
        password: ''
    })

    const changeHandler = event => {
        setForm({...form, [event.target.name]: event.target.value})
    }

    return(
        <section>
            <div className={style.container}>
                <div className={`${style.user} ${style.signinBg}`}>
                    <div className={style.imgBx}><img src={img}/></div>
                    <div className={style.formBx}>
                        <form>
                            <h2>Sign In</h2>
                            <input
                                type='text'
                                placeholder="Email"
                                id='email'
                                name='email'
                                onChange={changeHandler}

                            />
                            <input
                                type="password"
                                placeholder="Password"
                                id='password'
                                name='password'
                                onChange={changeHandler}
                            />
                            <input
                                type="submit"
                                value="Login"
                            />
                            <p
                                className={style.signup}>don't have an account?
                                <Link to={'/register'}
                                >
                                    Sign up</Link></p>
                        </form>
                    </div>
                </div>
            </div>
        </section>
    )
}