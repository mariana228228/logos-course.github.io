import styles from './MainPage.module.css'
import React, {useEffect, useRef, useState} from 'react'
import {init} from "ityped";
import {People} from "../peoples/People";
import {Portfolio} from "../Portfolio/Portfolio";
import Navbar from "../Navbar/Navbar";
import img from "./288_morya-grecii-4.jpg"
import {getDetails, postPhoto} from "../../redux/reducers/authReducer";
import {useDispatch, useSelector} from "react-redux";
import Footer from "../Footer/Footer";


const Main = () => {
    // const textRef = useRef();
    //
    // useEffect(()=> {
    //     init(textRef.current, {
    //         showCursor: true,
    //         backDelay: 1500,
    //         backSpeed: 60,
    //         strings: ['Developer', 'Hello']
    //     })
    // })
    const dispatch = useDispatch()
    const {userID} = useSelector(state => state.authReducer)

    useEffect(() => {
        dispatch(getDetails(userID))
    }, [userID])



const {userImage} = useSelector(state => state.authReducer)
    console.log(userImage)
    const postUserPhoto = (event) => {
        event.preventDefault()
        const formData = new FormData();
        formData.append("file",image);
        dispatch(postPhoto(formData))
    }


        const [image, setImage] = useState('https://www.kindpng.com/picc/m/78-785827_user-profile-avatar-login-account-male-user-icon.png')
        return (
            <div>
                <Navbar/>
                <div className={styles.container}>
                    <div className="right">
                        <div className="wrapper">
                            <h2>Hi There, I'm</h2>
                            <h1 className={styles.name}>Mariana Batig</h1>
                            <h4>
                                Web Developer
                            </h4>
                        </div>
                    </div>
              

                    <div>
                        <img className={styles.img} src={userImage}/>
                        <form onSubmit={(event) => postUserPhoto(event)}>

                            {/*<img src={image} alt={''}/>*/}
                            <input multiple={false} name="image" accept={'image/*'} type={'file'} onChange={(event) => {
                                setImage(event.target.files[0])
                            }}/>
                            <button type='submit'> Upload photo</button>
                        </form>
                    </div>
            </div>
                    <People/>
                <Footer/>

                </div>


        )
    }


        export default Main