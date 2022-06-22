import React, {useEffect, useState} from "react";
import styles from './Resume.module.css'
import {usePrevious} from "../../hook/UsePrevious";
import {useDispatch, useSelector} from "react-redux";
import {useParams} from "react-router-dom";
import {getDetails, postDetails} from "../../redux/reducers/authReducer";

import EditResume from "../../components/EditResume/EditResume";
import Navbar from "../Navbar/Navbar";
import Footer from "../Footer/Footer";


const ResumePage = () => {
    const {userId} = useParams()
    const myUserId = useSelector(state => state.authReducer.userID)

    const details = useSelector(state => state.resumeReducer)
    const dispatch = useDispatch()
    useEffect(() => {
        if (!userId) {
            dispatch(getDetails(myUserId))
        } else {
            dispatch(getDetails(userId))
        }

    }, [userId])


    const [edit, setEdit] = useState(false)

    const previous = usePrevious(details)

    const changeTextHandler = (e) => {
        dispatch({type: 'CHANGE', payload: {...details, [e.target.name]: e.target.value}})
    }
    const getUserPhoto = (e) => {
        e.preventDefault()
        const file = e.target[0].files[0]
        if(!file) return;
        const reader = new FileReader();
        reader.onloadend = () => {
            const base64 = reader.result;
            console.log(base64)
        }
        reader.readAsDataURL(file);
    }
    const toggle = () => {
        setEdit(!edit);
    }
    const save = (detail) => {
        dispatch(postDetails(userId || myUserId, detail))
        setEdit(false);
    }
    const cancel = () => {
        dispatch({type: 'CHANGE', payload: previous.value});
        setEdit(false);
    }
    return (
        <div>
            <Navbar/>
            <div className={styles.headerWrap}>
                {!userId ?
                    edit ? <div className={styles.buttons}>

                            <button className={styles.but} onClick={() => save(details)}>Save</button>
                            <button className={styles.but} onClick={cancel}>Cancel</button>
                        </div>

                        :
                        <button className={`${styles.buttonEdit} ${styles.button36}`} onClick={toggle}>Edit</button>
                    : null
                }
                <div className={styles.container}>
                    <div className={styles.text}>
                        <h1 className={styles.title}>
                            <EditResume
                                edit={edit}
                                onChange={changeTextHandler}
                                value={details.name}
                                name={'name'}
                                placeholder={'Name'}
                                className={`${styles.editableTypography} ${styles.nameInput}`}
                            />
                        </h1>
                        <h3 className={styles.aboutMe}>
                            <EditResume
                                edit={edit}
                                onChange={changeTextHandler}
                                value={details.title}
                                name={'title'}
                                placeholder={'About Me'}
                                className={`${styles.editableTypography} ${styles.titleInput}`}
                            /></h3>
                    </div>
                </div>
            </div>
            <section className={`${styles.about} ${styles.section}`}>

                <div><h1>About me</h1></div>

                <div className={styles.latoRegular}>
                    <EditResume
                        edit={edit}
                        onChange={changeTextHandler}
                        value={details.aboutMe}
                        name={'aboutMe'}
                        placeholder={' about'}
                        className={` ${styles.latoRegular}`}
                    />
                </div>

            </section>

            <section className={`${styles.about} ${styles.section}`}>
                <div>
                    <h4>Education</h4>
                </div>
                            <div className={styles.latoRegular}>
                                <EditResume
                                    edit={edit}
                                    onChange={changeTextHandler}
                                    value={details.courses}
                                    name={'courses'}
                                    placeholder={'courses ended'}
                                    className={` ${styles.latoRegular}`}
                                />
                            </div>


            </section>



            <section className={`${styles.contact} ${styles.section}`}>
                <div className={styles.contactIntro}>
                    <div className={`${styles.container} + ${styles.flex}`}>
                        <div className={styles.profile}>
                            <div className={styles.profileText}>
                                <h1 className={styles.profileTitle}>Profile</h1>
                                <p className={styles.profileText}>Lorem ipsum Qui veniam ut consequat ex ullamco nulla
                                    in non ut esse in magna sint minim officia consectetur nisi commodo ea magna
                                    pariatur nisi cillum.</p>
                            </div>
                            <div className={styles.profileFullname}>
                                <h3>FULLNAME :</h3>
                                <p>Mariana Batig</p>
                            </div>
                            <div className={styles.profileBirthDate}>
                                <h3>BIRTH DATE :</h3>
                                <p>25.06.2006</p>
                            </div>
                            <div className={styles.profileJob}>
                                <h3>JOB :</h3>
                                <p>Freelancer</p>
                            </div>
                            <div className={styles.profileWebsite}>
                                <h3>Website :</h3>
                                <p>www.website.com</p>
                            </div>
                            <div className={styles.profileEmail}>
                                <h3>EMAIL :</h3>
                                <p>maryanabatig123@gmail.com</p>
                            </div>
                        </div>
                        <div className={styles.skills}>
                            <h1 className={styles.skillsTitle}>Skills</h1>
                            <p className={styles.skillsText}>Lorem ipsum Qui veniam ut consequat ex ullamco nulla in non
                                ut esse in magna sint minim officia consectetur nisi commodo ea magna pariatur nisi
                                cillum.</p>
                        </div>
                    </div>
                </div>
            </section>
            <Footer/>
        </div>


    )
}
export default ResumePage