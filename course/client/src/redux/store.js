import {applyMiddleware,combineReducers,createStore} from "redux";
import thunk from "redux-thunk";
import { composeWithDevTools } from "redux-devtools-extension";
import {authReducer} from "./reducers/authReducer";
import resumeReducer from "./reducers/ResumeReducer";

const rootReducer = combineReducers({
    authReducer: authReducer,
    resumeReducer: resumeReducer
})
const composeEnhancers = composeWithDevTools({
    trace: true,
    traceLimit: 25,
});

const store = createStore(
    rootReducer,
    composeEnhancers(applyMiddleware(thunk))
)
window.store = store
export default store