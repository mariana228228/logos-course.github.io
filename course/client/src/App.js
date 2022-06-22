import React, {useEffect} from 'react'
// import  'materialize-css'
import 'react-toastify/dist/ReactToastify.css';
import RouterPage from "./components/navigation/Router";
import {useDispatch, useSelector} from "react-redux";
import {ToastContainer} from "react-toastify";
import {checkUserAuth} from "./redux/reducers/authReducer";
//

    const App = () => {
        const dispatch = useDispatch()
        const {isFirstLoading} = useSelector(state => state.authReducer)
        useEffect(() => {
            const token = localStorage.getItem('userToken')
            const userID = localStorage.getItem('userID')
            dispatch(checkUserAuth(token,userID))
        },[] )

        return (
            <>
                {!isFirstLoading ? <RouterPage/> : null }

                <ToastContainer
                    position="top-center"
                    autoClose={5000}
                    hideProgressBar={false}
                    newestOnTop={false}
                    closeOnClick
                    rtl={false}
                    pauseOnFocusLoss
                    draggable
                    pauseOnHover
                />
            </>

        )
}

export default App;
