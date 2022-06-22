import React from "react";
import styles from './Footer.module.css'
import MediaButt from "./MediaButtons/MediaButt";
import img from './free-icon-instagram-2111463.png'
import imgFace from './free-icon-facebook-174848.png'
import imgTeleg from './telegram.png'

const Footer = () => {
    return(
        <div>
            <div className={styles.container}>
                <div className={styles.Colum}>
                    <div className={styles.text}>
                        <p>Company</p></div>
                    <div className={styles.context}>
                        <p>About me</p>
                        <p>Services</p>
                        <p>Privacy Policy</p>
                        <p>Affiliate Program</p>
                    </div>
                </div>

                <div className={styles.Colum}>
                    <div className={styles.text}>
                        <p>Get Help</p></div>
                    <div className={styles.context}>
                        <p>FAQ</p>
                        <p>Shipping</p>
                        <p>Returns</p>
                        <p>Order Status</p>
                    </div>
                </div>

                <div className={styles.Colum}>
                    <div className={styles.text}>
                        <p>Online Shop</p></div>
                    <div className={styles.context}>
                        <p>Watch</p>
                        <p>Bag</p>
                        <p>Shoes</p>
                        <p>Dress</p>
                    </div>
                </div>


                <div className={styles.Colum}>
                    <div className={styles.text}>
                        <p>Get Help</p></div>
                    <div className={styles.icon}>
                   <a>    <img className={styles.img} src={img}/></a>
                    <a>    <img className={styles.img} src={imgFace}/></a>
                    <a>   <img className={styles.img} src={imgTeleg}/></a>
                    </div>
                </div>


            </div>
        </div>
    )
}

export default Footer;