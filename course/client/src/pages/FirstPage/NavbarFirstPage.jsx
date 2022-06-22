import React from "react";
import {Link} from "react-router-dom";
import styles from '../Navbar/Navbar.module.css'
import scss from '../Navbar/Nav.module.scss'


const Navbar = () => {

    return(
        <div>
            <div className={styles.container}>

                <div className={styles.nav}>
                    <div className={scss.btn}>
                       Mariana Batig
                    </div>
                    <div>

                        <Link  to='/login' >Login</Link>

                            <Link className={`${scss.btn} ${scss.fourth}` } to='/register' >Register</Link>

                    </div>
                </div>
            </div>


        </div>
    )

}

export default Navbar