export const actionsForAuth = {
    SET_USERS : "SET_USERS",
    SET_ERRORS : "SET_ERRORS",
    SET_REGISTRATION: 'SET_REGISTRATION',
    DELETE_AUTH: 'DELETE_AUTH',
    SET_USER_IMAGE: 'SET_USER_IMAGE',
    SET_DETAILS: 'SET_DETAILS',
    CAN_SAVE : 'CAN_SAVE',
    SET_VALUE : "SET_VALUE",
    SET_FIRST_LOADING: "SET_FIRST_LOADING"

}

export const actionUsers = {
    deleteAuth : () => ({type:actionsForAuth.DELETE_AUTH}),
    setLoading : (payload) => ({type: actionsForAuth.SET_FIRST_LOADING, payload}),
    setUsers : (id, token) => ({type:actionsForAuth.SET_USERS,token, id}),
    setUserImage: (photo) => ({type: actionsForAuth.SET_USER_IMAGE, photo}),
    setDetails : (props) => ({type:actionsForAuth.SET_DETAILS,payload:props}),
    canSave : (props) => ({type:actionsForAuth.CAN_SAVE,payload:props}),
    setValue : (props) => ({type:actionsForAuth.SET_VALUE,payload:props}),
    setRegistrationMessage : (message) => ({type:actionsForAuth.SET_REGISTRATION,payload:message}),
    setErrors : (error) => ({type:actionsForAuth.SET_ERRORS,error})
}
