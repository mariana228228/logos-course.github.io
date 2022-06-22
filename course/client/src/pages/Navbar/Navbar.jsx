import React from "react";
import {Link} from "react-router-dom";
import styles from './Navbar.module.css'
import img from './Mariana.jpg'
import LoginForm from "../LoginPage/LoginForm/LogForm";
import Main from "../Main/MainPage";
import {useDispatch} from "react-redux";
import {logoutUser} from "../../redux/reducers/authReducer";
// import './Butt'
import scss from './Nav.module.scss'


const Navbar = () => {

    const dispatch = useDispatch()
    const handleLogout = () =>{
        dispatch(logoutUser())
    }
    return(
        <div>
        <div className={styles.container}>

            <div className={styles.nav}>
                <div className={styles.img}>
                    {/*<img src={img}/>*/}
                </div>
                <div>
                <Link to='/navbar'>
                    Home
                    </Link>


                <Link to='/portfolio'>
                    portfolio
                </Link>


                <Link to='/resume'>
                    resume
                </Link>

                    <button className={`${scss.btn} ${scss.fourth}` } onClick={handleLogout}>
                       <Link to='/login' >Logout</Link>
                    </button>
                </div>
            </div>
        </div>

   
        </div>
    )

}

export default Navbar