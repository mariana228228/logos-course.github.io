import {BrowserRouter, Navigate, Route, Routes} from "react-router-dom";
import RegistrationPage from "../../pages/RegistrationPage/RegistrationPage";
import LoginPage from "../../pages/LoginPage/LoginPage";
import NotFoundPage from "../../pages/404/NotFoundPage";
import Navbar from "../../pages/Navbar/Navbar";
import {useSelector} from "react-redux";
import MainPage from "../../pages/Main/MainPage";
import Intro from "../../pages/Intro/Intro";
import FirstPage from "../../pages/FirstPage/FirstPage";
import {Portfolio} from "../../pages/Portfolio/Portfolio";
import Resume from "../../pages/Resume/Resume";

const RouterPage = () => {
    const  {token} = useSelector(state => state.authReducer)
    const isAuthenticated = !!token
    if (isAuthenticated) {
        return (
            <BrowserRouter>
                <div className='App'>
                    <Routes>
                        <Route path = '/navbar' element = {<MainPage />} />
                        <Route path = '/portfolio' element = {<Portfolio />} />
                        <Route path = '/resume' element = {<Resume />} />
                        <Route path="*" element={<Navigate to='/navbar'/>} />

                    </Routes>
                </div>
            </BrowserRouter>
        )
    }
    return (
        <BrowserRouter>
            <div className='App'>
                <Routes>

                    {/*<Route path = '/' element = {<Intro />} />*/}
                    <Route path = '/' element = {<FirstPage />} />
                    <Route path = '/register' element = {<RegistrationPage />} />
                    <Route path = '/login' element = {<LoginPage />} />
                    <Route path="*"  element={<Navigate to='/login'/>} />
                    {/*<Route path = {RouteConst.ADMIN} element = {<AdminPage />} />*/}
                </Routes>
            </div>
        </BrowserRouter>
    )
}
export default RouterPage