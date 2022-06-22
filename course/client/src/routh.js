// import React from "react";
// import {BrowserRouter, Redirect, Route, Routes} from "react-router-dom";
// import {LinksPage} from "./pages/LinksPage";
// import {CreatePage} from "./pages/CreatePage";
// import {DetailPage} from "./pages/DetailPage";
// import {AuthPage} from "./pages/AuthPage";
//
// export const useRoutes = isAuthenticated => {
//     if(isAuthenticated){
//         return(
//             <Routes>
//                 <Route path='/links'>
//                     <LinksPage/>
//                 </Route>
//                 <Route path='/create'>
//                    <CreatePage/>
//                 </Route>
//                 <Route path='/details/:id'>
//              <DetailPage/>
//             </Route>
//                 <Navigate to='/create'/>
//             </Routes>
//         )
//     }
//     return (
//         <Routes>
//         <Route path='/' exact>
//             <AuthPage/>
//         </Route>
//       <Redirect to='/'/>
//         </Routes>
//     )
//
// }
