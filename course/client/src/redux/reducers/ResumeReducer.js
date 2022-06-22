import {actionsForAuth} from "../actionsCreator/authCreator";

const initialState = {
    canSave:false,
    email: '',
    username : '',
    name: '',
    title: '',
    aboutMe: '',
    courses: '',
    coursesName: '',
    coursesTime: '',
    coursesGratuation: '',
    coursesSecond: '',
    coursesNameSecond: '',
    coursesTimeSecond: '',
    coursesGratuationSecond: ''
}



export const resumeReducer = (state = initialState,action) => {
    switch(action.type){
        case actionsForAuth.SET_DETAILS:
            return({
                ...state,
                ...action.payload
            })
        case actionsForAuth.CAN_SAVE :
            return({
                ...state,
                canSave:action.payload
            })
        case 'CHANGE' :
            return({
                ...state,
                ...action.payload
            })
        default:
            return state

    }
}
export default resumeReducer;