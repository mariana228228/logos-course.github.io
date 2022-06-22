import {actionsForAuth, actionUsers} from "../actionsCreator/authCreator";
import {loginAPI, registerAPI, UsersAPI} from "../../api/api";
import {checkAPI} from "../../api/api";
import {toast} from "react-toastify";
// import {useEffect} from "react";
// import axios from 'axios'

const initialState = {
    token:null,
    canSave:false,
    userID:null,
    errorUsers: '',
    isAuth:false,
    isFirstLoading: true,
    isRegistrated:false,
    userImage: 'https://q-xx.bstatic.com/xdata/images/hotel/840x460/78809294.jpg?k=cf850d507a9671cf7ff85d598435ea329a28cd4f1b1abc25c1892c91156d36ad&o='
}
const setAuthAction = ({userID, token}) => {
    return dispatch => {
        localStorage.setItem('userToken',token)
        localStorage.setItem('userID',userID)
        dispatch(actionUsers.setUsers(userID,token))
    }
}
    // localStorage.setItem('userData',JSON.stringify({
    //     token,userID
    // }))
export const authReducer = (state = initialState,action) => {
    switch(action.type){
        case actionsForAuth.SET_USERS:
            return({
                ...state,
                token:action.token,
                userID: action.id,
                isAuth: true
            })
        case actionsForAuth.DELETE_AUTH:
            return ({
                ...state,
                token: null,
                userID: null,
                isAuth:false,
                isRegistrated:false

            })

        case actionsForAuth.SET_USER_IMAGE:
            return ({
                ...state,
                userImage: action.photo
            })

        case actionsForAuth.SET_FIRST_LOADING:
            return ({
                ...state,
                isFirstLoading: action.payload
            })
        case actionsForAuth.SET_REGISTRATION:
            return {
                ...state,
                isRegistrated:true
            }
        case actionsForAuth.SET_ERRORS:
            return{
                ...state,
                errorUsers: action.error
            }
        default:
            return state

    }
}
export const registerUser = ({username,email,password}) =>  (dispatch) => {
    registerAPI.postsUsers({username,email,password})
        .then(response => {
           if(response.status === 201){
                dispatch(actionUsers.setRegistrationMessage(response.data.message))
           }else{
               dispatch(actionUsers.setErrors(response.data.message))
           }
        })
}
export const loginUser = ({email, password}) => async (dispatch) => {
    await loginAPI.loginUsers({email, password})
        .then((response) => {
            if (response.message) {
                dispatch(setAuthAction({...response}))
            } else {
                dispatch(actionUsers.setErrors(response.data.message))
            }

        })

}

export const checkUserAuth = (token, userID) => (dispatch) => {
    checkAPI.checkAuth(token).then(response => {
        if (response.status === 204) {
            dispatch(actionUsers.setUsers(userID, token))
        }
    }).catch((e) => {
        localStorage.removeItem('userToken')
        localStorage.removeItem('userID')
    }).finally(() => {
        dispatch(actionUsers.setLoading(false))
    })

}
export const logoutUser = () => {
    return dispatch => {
        localStorage.clear()
        dispatch(actionUsers.deleteAuth())
    }
}




export const postPhoto = (formData) => async(dispatch,getState) =>{
    const {token} = getState().authReducer

    const response = await UsersAPI.postImage(token,formData)
    dispatch(actionUsers.setUserImage(response.data.userImage))
}

export const getDetails = (userID) => async(dispatch,getState) => {
    const {token} = getState().authReducer
    const response = await UsersAPI.getDetails(token, userID)
    dispatch(actionUsers.setUserImage(response.data.user.userImage))
}



export const postDetails = (userId,detail) => async (dispatch,getState) => {
    const {token} = getState().authReducer

    const response = await UsersAPI.postDetails(token,userId,detail)
    if(response.status === 400){
        toast.error(response.data.message, {
            position: "top-center",
            autoClose: 5000,
            hideProgressBar: false,
            closeOnClick: true,
            pauseOnHover: true,
            draggable: true,
        });
    }else{
        console.log(detail)
        dispatch(actionUsers.setValue(detail))
    }

}

export default authReducer