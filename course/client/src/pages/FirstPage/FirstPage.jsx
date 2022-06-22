import React from "react";
import NavbarFirstPage from "./NavbarFirstPage";
import s from './FirstPage.module.css'
import CssEffect from "./CssEffect/CssEffect";
import Footer from "../Footer/Footer";

const FirstPage = () => {
    return(


        <div>
            <NavbarFirstPage/>

            <div className={s.container}>
                WELLCOME TO MARIANA'S PAGE

            <CssEffect/>
            </div>
            <Footer/>
        </div>
    )
}

export default FirstPage