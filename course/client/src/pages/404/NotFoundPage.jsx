import React from 'react'
import s from  './NotFoundPage.module.css'
import img from '../img/plane.png'
const NotFoundPage = () => {
    return(
        <div className={s.container}>
    <div className={s.error}>
    <div className={s.sky}>
        <h2><span>4</span><span>0</span><span>4</span></h2>
        <div className={s.grass}></div>
        <img className={s.plane} src={img}/>
    </div>
        <div className={s.field}>
            <h2>Opps...looks like you got lost</h2>

        </div>
    </div>
        </div>
    )}

export default NotFoundPage;